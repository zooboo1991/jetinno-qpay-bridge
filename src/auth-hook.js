import express from 'express';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { query } from './db.js';
import { sendSms, smsConfigured } from './sms.js';

/**
 * Supabase's "Send SMS" auth hook.
 *
 * Supabase's built-in SMS providers are Twilio, MessageBird, Vonage and
 * Textlocal — all international A2P routes into Mongolia, which are expensive
 * and deliver unevenly. This hook is how a domestic gateway gets used instead:
 * Supabase POSTs the code here, and this sends it on.
 *
 * That makes this endpoint the one place in the system where an HTTP request
 * from the internet causes money to be spent and a stranger's phone to ring.
 * Everything below is about that.
 */

const SECRET = process.env.SEND_SMS_HOOK_SECRET ?? '';

/** Refuses to mount without a secret, rather than mounting one that verifies nothing. */
export function authHookConfigured() {
  return Boolean(SECRET) && smsConfigured();
}

/*
 * Standard Webhooks (https://www.standardwebhooks.com).
 *
 * Three headers: `webhook-id`, `webhook-timestamp` (unix seconds) and
 * `webhook-signature`, the last being a space-separated list of
 * `v1,<base64 hmac>`. The signed string is `id.timestamp.rawBody` and the key
 * is the base64 body of the `v1,whsec_…` secret.
 *
 * The raw body matters: re-serialising the parsed JSON produces a different
 * byte string — different key order, different spacing — and the signature
 * then never matches. So this router takes the body as a Buffer and parses it
 * itself, after verifying.
 */
const TOLERANCE_SECONDS = 300;

function secretKey() {
  const body = SECRET.replace(/^v1,/, '').replace(/^whsec_/, '');
  return Buffer.from(body, 'base64');
}

function verifySignature(rawBody, headers) {
  const id = headers['webhook-id'];
  const timestamp = headers['webhook-timestamp'];
  const signature = headers['webhook-signature'];
  if (!id || !timestamp || !signature) return { ok: false, why: 'missing headers' };

  // Replay protection. Without it a captured request can be sent again for as
  // long as the secret lives, and each replay is another SMS.
  const age = Math.abs(Math.floor(Date.now() / 1000) - Number(timestamp));
  if (!Number.isFinite(age) || age > TOLERANCE_SECONDS) return { ok: false, why: 'stale timestamp' };

  const expected = createHmac('sha256', secretKey())
    .update(`${id}.${timestamp}.${rawBody.toString('utf8')}`)
    .digest();

  // The header may carry several signatures during a secret rotation; any one
  // matching is a pass.
  for (const part of String(signature).split(' ')) {
    const [version, value] = part.split(',');
    if (version !== 'v1' || !value) continue;
    const given = Buffer.from(value, 'base64');
    // timingSafeEqual throws on a length mismatch, which is itself a leak of
    // one bit — so the lengths are compared first and both paths cost the same.
    if (given.length === expected.length && timingSafeEqual(given, expected)) {
      return { ok: true };
    }
  }
  return { ok: false, why: 'no matching signature' };
}

/**
 * The message. Deliberately short and deliberately boring.
 *
 * No link, because a login code beside a link is the exact shape of every
 * phishing SMS and teaches owners to tap one. The sender name carries the
 * brand; the body carries the code and what it is for.
 */
function otpMessage(code) {
  return `Coffeine нэвтрэх код: ${code}. Хэнд ч бүү дамжуул.`;
}

export function authHook({ log = () => {} } = {}) {
  const router = express.Router();

  router.post(
    '/send-sms',
    // Raw, not parsed: the signature covers the bytes Supabase sent.
    express.raw({ type: '*/*', limit: '16kb' }),
    async (req, res) => {
      const check = verifySignature(req.body, req.headers);
      if (!check.ok) {
        log('send-sms rejected', check.why);
        // 401 rather than 200. Supabase surfaces the failure instead of
        // believing a code was delivered that never was.
        return res.status(401).json({ error: { message: 'unauthorized' } });
      }

      let payload;
      try {
        payload = JSON.parse(req.body.toString('utf8'));
      } catch {
        return res.status(400).json({ error: { message: 'bad payload' } });
      }

      const phone = payload?.user?.phone;
      const code = payload?.sms?.otp;
      if (!phone || !code) {
        log('send-sms rejected', 'missing phone or otp');
        return res.status(400).json({ error: { message: 'bad payload' } });
      }

      try {
        // Invite-only, enforced in SQL. Without this, anyone can type any
        // Mongolian number into the login screen and make us text it.
        const { rows: gate } = await query(`select app.phone_may_receive_otp($1) as allowed`, [
          phone,
        ]);
        if (!gate[0]?.allowed) {
          // Logged without the number: this fires on typos as well as abuse,
          // and a log of phone numbers that tried to log in is a list worth
          // not keeping.
          log('send-sms refused', 'phone not invited');
          return res.status(403).json({ error: { message: 'not permitted' } });
        }

        const { rows: budget } = await query(`select * from app.sms_budget($1)`, [phone]);
        if (!budget[0]?.out_allowed) {
          log('send-sms refused', budget[0]?.out_reason ?? 'budget');
          return res.status(429).json({
            error: {
              message: `Дахин код авахын тулд ${budget[0]?.out_retry_minutes ?? 60} минут хүлээнэ үү.`,
            },
          });
        }

        const result = await sendSms(phone, otpMessage(code));
        await query(`select app.record_sms_send($1, 'otp', $2, $3, $4)`, [
          phone,
          result.ok,
          result.status ?? null,
          result.ok ? null : (result.error ?? null),
        ]);

        if (!result.ok) {
          log('send-sms gateway failed', result.status ?? '-', String(result.error).slice(0, 80));
          return res.status(502).json({ error: { message: 'SMS илгээж чадсангүй.' } });
        }

        log('send-sms ok', `…${String(phone).slice(-4)}`);
        // Supabase treats 200 with an empty object as delivered.
        return res.status(200).json({});
      } catch (err) {
        // The code is in scope in this function; nothing from here may be
        // echoed to the caller, and err.message can carry a query parameter.
        log('send-sms failed', err.message.split('\n')[0]);
        return res.status(500).json({ error: { message: 'internal error' } });
      }
    }
  );

  return router;
}
