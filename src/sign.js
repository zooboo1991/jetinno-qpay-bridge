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

export function verifySign(body, keys, apikey) {
  const flat = flatten(body);
  const expected = buildSign(flat, keys, apikey, flat.nonce ?? '');
  const got = String(body?.sign ?? '').toUpperCase();
  return { ok: expected === got, expected, got };
}

export function timestamp(d = new Date()) {
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
}
