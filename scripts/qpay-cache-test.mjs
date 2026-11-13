/**
 * QPay token cache. Run: npm run test:qpay
 *
 * A credential is re-pointed at another merchant IN PLACE, under the same id,
 * while orders invoiced on the old merchant are still open and still hold
 * the old client. Keyed by credential id alone, the two clients shared one
 * token: old-merchant tokens on new invoices, new-merchant tokens checking old
 * payments. Each merchant login now has its own slot. No database, no network.
 */
import { createServer } from 'node:http';

const QPAY_PORT = 4615;
process.env.QPAY_BASE_URL = `http://127.0.0.1:${QPAY_PORT}`;
const qpay = await import('../src/qpay.js');

const tokensIssued = [];
const used = []; // { path, bearer, invoiceCode }
const fake = createServer((req, res) => {
  let body = '';
  req.on('data', (d) => (body += d));
  req.on('end', () => {
    const auth = req.headers.authorization ?? '';
    res.setHeader('content-type', 'application/json');
    if (req.url === '/v2/auth/token') {
      const [user] = Buffer.from(auth.replace('Basic ', ''), 'base64').toString().split(':');
      tokensIssued.push(user);
      if (user === 'bad') {
        res.statusCode = 401;
        return res.end(JSON.stringify({ error: 'AUTHENTICATION_FAILED', message: `user ${user} not found` }));
      }
      return res.end(JSON.stringify({ access_token: `tok-${user}`, expires_in: 3600 }));
    }
    const j = body ? JSON.parse(body) : {};
    used.push({ path: req.url, bearer: auth.slice(7), invoiceCode: j.invoice_code });
    if (req.url === '/v2/invoice') return res.end(JSON.stringify({ invoice_id: `i${used.length}`, qPay_shortUrl: 'https://s/x' }));
    if (req.url === '/v2/payment/check') return res.end(JSON.stringify({ rows: [] }));
    res.end('{}');
  });
});
await new Promise((r) => fake.listen(QPAY_PORT, '127.0.0.1', r));

const results = [];
const check = async (name, fn) => {
  try {
    const ok = await fn();
    results.push([ok === true, name, ok === true ? '' : ` — ${JSON.stringify(ok)}`]);
  } catch (err) {
    results.push([false, name, ` — ${err.message.split('\n')[0]}`]);
  }
};

const invoice = (client, n) => client.createInvoice({ orderNo: `o${n}`, amount: 10, description: 'x', callbackUrl: 'https://cb' });

await check('нэг credential id-д хуучин, шинэ мерчант тус бүрийн token-оо хэрэглэнэ', async () => {
  const oldMerchant = qpay.clientFor({ username: 'merchantA', password: 'pa', invoiceCode: 'INV_A', cacheKey: 'cred-1' });
  const newMerchant = qpay.clientFor({ username: 'merchantB', password: 'pb', invoiceCode: 'INV_B', cacheKey: 'cred-1' });
  await invoice(oldMerchant, 1); // caches A's token first, like an old order's sweep
  await invoice(newMerchant, 2); // a new sale on the switched credential
  await oldMerchant.checkPayment('i1');
  const [a, b, c] = used.slice(-3);
  return (a.bearer === 'tok-merchantA' && b.bearer === 'tok-merchantB' && b.invoiceCode === 'INV_B' &&
    c.bearer === 'tok-merchantA') || used.slice(-3);
});

await check('зөвхөн нууц үг солигдвол (ижил нэвтрэх нэр) token-ыг хуваалцана — QPay-ээс дахин авахгүй', async () => {
  const before = tokensIssued.length;
  const again = qpay.clientFor({ username: 'merchantA', password: 'pa-new', invoiceCode: 'INV_A', cacheKey: 'cred-1' });
  await invoice(again, 3);
  return (tokensIssued.length === before && used.at(-1).bearer === 'tok-merchantA') || { issued: tokensIssued.length - before };
});

await check('evictCredential тухайн credential-ийн бүх мерчантын token-ыг цэвэрлэнэ', async () => {
  qpay.evictCredential('cred-1');
  const before = tokensIssued.length;
  await invoice(qpay.clientFor({ username: 'merchantA', password: 'pa', invoiceCode: 'INV_A', cacheKey: 'cred-1' }), 4);
  await invoice(qpay.clientFor({ username: 'merchantB', password: 'pb', invoiceCode: 'INV_B', cacheKey: 'cred-1' }), 5);
  return tokensIssued.length - before === 2 || { issued: tokensIssued.length - before };
});

await check('QPay-ийн алдааны мессежид хариуны бие (нэвтрэх нэр) орохгүй, зөвхөн код', async () => {
  try {
    await invoice(qpay.clientFor({ username: 'bad', password: 'x', invoiceCode: 'INV', cacheKey: 'cred-2' }), 6);
    return 'did not throw';
  } catch (err) {
    return (err.message === 'qpay auth 401: AUTHENTICATION_FAILED' && err.status === 401 && !err.message.includes('bad')) ||
      err.message;
  }
});

fake.close();
const passed = results.filter(([ok]) => ok).length;
for (const [ok, name, extra] of results) console.log(`  ${ok ? '✓' : '✗'} ${name}${extra}`);
console.log(`\n  ${passed}/${results.length} давлаа`);
process.exit(passed === results.length ? 0 : 1);
