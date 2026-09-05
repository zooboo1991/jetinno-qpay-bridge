/**
 * Outbound SMS through a Mongolian HTTP gateway.
 *
 * Configured rather than coded per provider: Skytel Web2SMS, Messagepro and
 * Mobicom all expose the same shape — one HTTP call with the number, the text
 * and a key as parameters — and the differences are only in what those
 * parameters are called. A gateway change is then an environment change, not
 * a deploy, which matters on the day the account being billed moves from one
 * operator to another.
 *
 * Skytel Web2SMS is what gmath.mn has been sending on for two months,
 * including to Mobicom and Unitel numbers, so cross-network delivery is
 * settled by that rather than by a promise in a datasheet.
 */

const CONFIG = {
  url: process.env.SMS_API_URL ?? '',
  // POST by default. Skytel Web2SMS has no HTTPS listener at all — port 443
  // does not answer — so the request crosses the network in the clear either
  // way. POST at least keeps the login code and the API token out of the URL,
  // and therefore out of every access log along the path that records one.
  // Verified against the live endpoint: POST with a form body is parsed
  // identically to the query string.
  method: (process.env.SMS_API_METHOD ?? 'POST').toUpperCase(),
  paramTo: process.env.SMS_PARAM_TO ?? 'sendto',
  paramText: process.env.SMS_PARAM_TEXT ?? 'message',
  paramKey: process.env.SMS_PARAM_KEY ?? 'token',
  paramFrom: process.env.SMS_PARAM_FROM ?? '',
  from: process.env.SMS_FROM ?? '',
  apiKey: process.env.SMS_API_KEY ?? '',
  extra: process.env.SMS_EXTRA_PARAMS ?? '',
  // Gateways answer 200 with the failure in the body. Either a literal
  // substring or a pattern; the pattern exists because the useful signal is
  // usually a JSON field whose spacing is not guaranteed.
  errorMatch: process.env.SMS_ERROR_MATCH ?? '',
  errorRegex: process.env.SMS_ERROR_REGEX ?? '',
  transliterate: process.env.SMS_TRANSLITERATE !== 'false',
};

export function smsConfigured() {
  return Boolean(CONFIG.url && CONFIG.apiKey);
}

/*
 * Skytel Web2SMS garbles Cyrillic, so the text goes out in Latin.
 *
 * This is not a nicety: a garbled message containing a login code reads as a
 * broken app, and the owner's first instinct is that the code is wrong rather
 * than that the font is. gmath.mn and rkh-club both transliterate for the
 * same reason.
 */
const CYRILLIC = {
  а: 'a', б: 'b', в: 'v', г: 'g', д: 'd', е: 'e', ё: 'yo', ж: 'j', з: 'z',
  и: 'i', й: 'i', к: 'k', л: 'l', м: 'm', н: 'n', о: 'o', ө: 'u', п: 'p',
  р: 'r', с: 's', т: 't', у: 'u', ү: 'u', ф: 'f', х: 'h', ц: 'ts', ч: 'ch',
  ш: 'sh', щ: 'sh', ъ: '', ы: 'y', ь: '', э: 'e', ю: 'yu', я: 'ya',
};

export function toLatin(text) {
  return [...text]
    .map((ch) => {
      const lower = ch.toLowerCase();
      const mapped = CYRILLIC[lower];
      if (mapped === undefined) return ch;
      if (ch === lower) return mapped;
      return mapped.charAt(0).toUpperCase() + mapped.slice(1);
    })
    .join('');
}

/**
 * Mongolian mobile numbers are eight digits; the gateways want them bare.
 *
 * Supabase hands over E.164 without the '+' — `97699112233` — and the country
 * code has to come off before it reaches a domestic gateway, which would
 * otherwise send to a number that does not exist.
 */
export function localNumber(phone) {
  const digits = String(phone).replace(/\D/g, '');
  return digits.length > 8 && digits.startsWith('976') ? digits.slice(3) : digits;
}

/**
 * Sends one message. Resolves with the outcome rather than throwing, because
 * every caller has to record what happened either way.
 *
 * The timeout is short and deliberate: this call sits inside Supabase's own
 * request to our hook, and a gateway that hangs turns "the code did not
 * arrive" into "the login button did nothing", which is a worse thing to
 * explain over the phone.
 */
function reportsFailure(replyText) {
  if (!replyText.trimStart().startsWith('{')) return false;
  try {
    const json = JSON.parse(replyText);
    if (json.status === 0 || json.status === false || json.status === '0') return true;
    if (typeof json.sent_count === 'number' && json.sent_count === 0) return true;
    return false;
  } catch {
    return false;
  }
}

export async function sendSms(phone, text, { timeoutMs = 6000 } = {}) {
  if (!smsConfigured()) return { ok: false, status: null, error: 'SMS_NOT_CONFIGURED' };

  const body = CONFIG.transliterate ? toLatin(text) : text;
  const params = new URLSearchParams();
  params.set(CONFIG.paramTo, localNumber(phone));
  params.set(CONFIG.paramText, body);
  if (CONFIG.paramKey) params.set(CONFIG.paramKey, CONFIG.apiKey);
  if (CONFIG.paramFrom && CONFIG.from) params.set(CONFIG.paramFrom, CONFIG.from);
  for (const [k, v] of new URLSearchParams(CONFIG.extra)) params.set(k, v);

  const headers = {};
  // Gateways that want the key in a header instead of the query string.
  if (!CONFIG.paramKey && CONFIG.apiKey) headers.authorization = `Bearer ${CONFIG.apiKey}`;

  try {
    const isGet = CONFIG.method === 'GET';
    const url = isGet ? `${CONFIG.url}?${params}` : CONFIG.url;
    const res = await fetch(url, {
      method: CONFIG.method,
      headers: isGet
        ? headers
        : { ...headers, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: isGet ? undefined : params.toString(),
      signal: AbortSignal.timeout(timeoutMs),
    });
    const replyText = (await res.text()).slice(0, 200);

    if (!res.ok) return { ok: false, status: res.status, error: replyText };
    if (CONFIG.errorMatch && replyText.includes(CONFIG.errorMatch)) {
      return { ok: false, status: res.status, error: replyText };
    }
    if (CONFIG.errorRegex && new RegExp(CONFIG.errorRegex).test(replyText)) {
      return { ok: false, status: res.status, error: replyText };
    }
    // Fail closed on a JSON body that reports its own failure, whatever the
    // configuration says. The two mistakes are not equal: a false failure
    // shows an error the owner can retry past, while a false success spends
    // the send, consumes their hourly budget, and leaves them waiting for a
    // code we believe we delivered.
    if (reportsFailure(replyText)) {
      return { ok: false, status: res.status, error: replyText };
    }
    return { ok: true, status: res.status, reply: replyText };
  } catch (err) {
    // AbortError included: a timeout is a failed send, not a crash.
    return { ok: false, status: null, error: err.name === 'TimeoutError' ? 'TIMEOUT' : err.message };
  }
}
