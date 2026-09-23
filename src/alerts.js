import * as store from './store.js';
import { sendSms, smsConfigured } from './sms.js';

/**
 * The two ways this system asks a human to look at something.
 *
 * Neither ever throws and neither is ever awaited by a request handler. An
 * alert that can fail a credential change is worse than a missed alert: the
 * change has already happened, and refusing the response would leave the
 * owner believing it had not.
 *
 * Nothing here takes an error object or a request body. The one caller that
 * matters — src/credentials.js — is the only path in this system that ever
 * holds a plaintext merchant password, and a logger that accepts an arbitrary
 * object is exactly how such a thing reaches a table somebody reads casually.
 * Named scalars only.
 */

const OPERATOR_PHONE = process.env.OPERATOR_ALERT_PHONE ?? '';

function line(text) {
  process.stdout.write(`${new Date().toISOString()} ALERT ${text}\n`);
}

/**
 * Something needs an operator's attention.
 *
 * Written to public.ingest_errors, which is already what GET /errors reads —
 * so these land on the page the operator can open from a phone on site,
 * rather than in a separate channel nobody has built yet. `context` is
 * stringified into the reason, not into the payload column: payload is jsonb
 * and a tempting place to put a request body, and this function is called
 * from the credential path.
 */
export function pageOperator(message, context = {}) {
  const parts = Object.entries(context)
    .filter(([, v]) => v !== undefined && v !== null)
    .map(([k, v]) => `${k}=${String(v).slice(0, 80)}`)
    .join(' ');
  const reason = `OPERATOR: ${message}${parts ? ` (${parts})` : ''}`.slice(0, 300);
  line(reason);

  store
    .logIngestError({ path: '/alerts/pageOperator', reason })
    .catch((err) => line(`page failed to persist: ${err.message.split('\n')[0]}`));

  if (OPERATOR_PHONE && smsConfigured()) {
    // Latin, short, no link: this goes through the same gateway as the login
    // codes, and the operator reads it on a phone.
    sendSms(OPERATOR_PHONE, `Coffeine: ${message}`.slice(0, 160)).catch(() => {});
  }
}

/**
 * Tells an owner that the QPay account behind their machine has changed.
 *
 * DETECTION, NOT PREVENTION. Someone holding a stolen owner session can
 * redirect that owner's future revenue, and nothing in the credential flow
 * stops them. This message is what makes it survivable: the owner finds out
 * within a minute and can phone the operator.
 *
 * The recipient is owners.contact_phone — the number on the sales paperwork —
 * and NOT the phone on the session that made the change. A hijacked identity
 * would otherwise silence its own alarm.
 *
 * No link in the body, ever. Every other message this system sends an owner
 * also has no link, and the day one does is the day a phishing SMS becomes
 * indistinguishable from ours.
 */
export async function notifyOwnerCredentialChanged(ownerId) {
  if (!smsConfigured()) {
    line(`owner ${ownerId} credential changed — SMS not configured, not sent`);
    return;
  }
  let phone;
  try {
    phone = await store.ownerContactPhone(ownerId);
  } catch (err) {
    line(`owner lookup failed: ${err.message.split('\n')[0]}`);
    return;
  }
  if (!phone) {
    pageOperator('owner has no contact phone for a credential-change alert', { ownerId });
    return;
  }

  const result = await sendSms(
    phone,
    'Coffeine: Таны кофе машины QPay данс солигдлоо. Та үүнийг хийгээгүй бол яаралтай холбогдоно уу.'
  );
  if (!result.ok) {
    pageOperator('credential-change alert to owner failed', { ownerId, status: result.status });
  }
}
