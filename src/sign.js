import crypto from 'node:crypto';

export const SIGNABLE = {
  getQrCodeRequest: ['username', 'time', 'deviceNo', 'productId', 'productName', 'orderNo', 'orderAmount', 'notifyUrl'],
  getQrCodeResponse: ['returnCode', 'msg', 'time', 'deviceNo', 'orderNo', 'qrCode'],
  paymentCallback: ['username', 'time', 'deviceNo', 'orderNo', 'orderAmount', 'payType', 'payStatus'],
  refundRequest: ['username', 'time', 'deviceNo', 'orderNo', 'refundAmount'],
  productDoneRequest: ['username', 'time', 'deviceNo', 'productId', 'orderNo', 'orderAmount', 'isFinish'],
};

export function flatten(body) {
  const { data, sign, ...top } = body ?? {};
  return { ...top, ...(data ?? {}) };
}

export function buildSign(flat, keys, apikey, nonce = '') {
  const string = keys
    .filter((k) => flat[k] !== undefined && flat[k] !== null && flat[k] !== '')
    .sort()
    .map((k) => `${k}=${flat[k]}`)
    .join('&');
  return crypto.createHash('md5').update(`${nonce}${string}${apikey}`, 'utf8').digest('hex').toUpperCase();
}

/*
 * Values are joined unescaped, so a value carrying `&payStatus=PAYSUCCESS`
 * makes one message's signing string equal another's: a getQrCode whose
 * orderNo ends in the right suffix is signed exactly like a PAYSUCCESS for
 * that order. Any signed value (or the nonce, which is prepended raw) that
 * contains `&<one of the protocol's keys>=` is refused. A plain `&` — a
 * product called "Latte & Milk" — still passes.
 *
 * notifyUrl is exempt: a URL's query string is made of exactly such pairs,
 * Jetinno's own notify endpoint may well carry one, and refusing it would
 * stop every sale. It is the one value whose shape we do not control.
 */
const PROTOCOL_KEYS = [...new Set([...Object.values(SIGNABLE).flat(), 'nonce', 'sign', 'refundState'])];
const INJECTED = new RegExp(`(?:^|&)(?:${PROTOCOL_KEYS.join('|')})=`, 'i');

export function verifySign(body, keys, apikey) {
  const flat = flatten(body);
  const nonce = flat.nonce ?? '';
  const checked = keys.filter((k) => k !== 'notifyUrl').map((k) => flat[k]);
  const injected = [...checked, nonce].some(
    (v) => v !== undefined && v !== null && INJECTED.test(String(v))
  );
  const expected = buildSign(flat, keys, apikey, nonce);
  const got = String(body?.sign ?? '').toUpperCase();
  // Constant time: the comparison of a secret-derived value.
  const ok =
    !injected &&
    got.length === expected.length &&
    crypto.timingSafeEqual(Buffer.from(got), Buffer.from(expected));
  // `expected` is deliberately NOT returned. Logged once, it was a valid
  // signature for whatever the caller sent — a signing oracle for anyone
  // who can read the log.
  return { ok, injected };
}

export function timestamp(d = new Date()) {
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
}
