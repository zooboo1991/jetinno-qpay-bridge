import express from 'express';
import { SIGNABLE, buildSign, verifySign, flatten, timestamp } from './sign.js';

const APIKEY = process.env.JETINNO_APIKEY ?? 'DBRW17YE7FHKR72T';
const USERNAME = process.env.JETINNO_USERNAME ?? 'testname';
const BRIDGE = process.env.BRIDGE_URL ?? 'http://localhost:3000';
const MACHINE_PORT = Number(process.env.MACHINE_PORT ?? 4000);
const notifyUrl = `http://localhost:${MACHINE_PORT}/notify`;

const machine = express();
machine.use(express.json());
machine.post('/notify', (req, res) => {
  const check = verifySign(req.body, SIGNABLE.paymentCallback, APIKEY);
  const { orderNo, payStatus, productId } = flatten(req.body);
  console.log(`\n[machine] callback sign=${check.ok ? 'OK' : 'BAD'} order=${orderNo} status=${payStatus}`);
  if (check.ok && payStatus === 'PAYSUCCESS') console.log(`[machine] >>> Кофе гаргаж байна (productId=${productId ?? 'сонгосон төрөл'}) <<<\n`);
  res.json({ returnCode: 'SUCCESS', msg: 'SUCCESS' });
});

machine.listen(MACHINE_PORT, async () => {
  const orderNo = process.env.TEST_ORDER_NO ?? `TEST${Date.now()}`;
  const data = {
    deviceNo: process.env.JETINNO_DEVICE_NO ?? '44401',
    productId: process.env.TEST_PRODUCT_ID ?? '1',
    productName: '拿铁',
    orderNo,
    orderAmount: process.env.TEST_AMOUNT ?? '100000',
    notifyUrl,
  };
  const body = { username: USERNAME, time: timestamp(), data };
  body.sign = buildSign(flatten(body), SIGNABLE.getQrCodeRequest, APIKEY);

  console.log('[machine] getQrCode ->', JSON.stringify(body, null, 2));
  const res = await fetch(`${BRIDGE}/jetinno/getQrCode`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const reply = await res.json();
  console.log('[machine] getQrCode <-', JSON.stringify(reply, null, 2));

  if (reply.returnCode !== 'SUCCESS') return process.exit(1);
  console.log(`\n[machine] Дэлгэц дээр QR харагдаж байна: ${reply.data.qrCode}`);
  console.log(`[machine] Төлбөрийг дуурайхын тулд: curl ${BRIDGE}/mock/pay/${orderNo}\n`);
});
