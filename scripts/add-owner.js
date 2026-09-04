/**
 * Registers an owner, seals their QPay credentials, and binds a machine.
 *
 *   DATABASE_URL=... CRED_KEYS=k1:... CRED_KEY_ACTIVE=k1 CRED_FP_KEY=... \
 *     node scripts/add-owner.js
 *
 * Why a CLI rather than a SQL snippet: pasting a plaintext QPay password into
 * the Supabase SQL editor writes it into that editor's query history, where it
 * outlives the session and is readable by anyone with dashboard access. The
 * password must arrive at the database already sealed.
 *
 * The password is typed, never echoed, never logged, and never on argv — argv
 * is readable by every process on the host via `ps`.
 *
 * All the work is in src/register-owner.js; this file is only input.
 */
import { createInterface } from 'node:readline/promises';
import { stdin, stdout } from 'node:process';
import { close, configured } from '../src/db.js';
import { assertCryptoUsable } from '../src/crypto.js';
import { registerOwner } from '../src/register-owner.js';

if (!configured()) {
  console.error('DATABASE_URL тохируулаагүй байна.');
  process.exit(1);
}
assertCryptoUsable();

const rl = createInterface({ input: stdin, output: stdout });

const ask = async (label, { required = true } = {}) => {
  for (;;) {
    const value = (await rl.question(label)).trim();
    if (value || !required) return value;
    console.log('  Заавал бөглөнө үү.');
  }
};

/** Reads without echoing. A shoulder is as good a leak as a log file. */
async function askSecret(label) {
  stdout.write(label);
  const wasRaw = Boolean(stdin.isRaw);
  stdin.setRawMode?.(true);
  let value = '';
  try {
    for await (const chunk of stdin) {
      const s = chunk.toString('utf8');
      if (s === '\r' || s === '\n') break;
      if (s === '') {
        console.log();
        process.exit(130);
      }
      if (s === '' || s === '\b') {
        value = value.slice(0, -1);
        continue;
      }
      value += s;
    }
  } finally {
    stdin.setRawMode?.(wasRaw);
  }
  console.log();
  return value;
}

console.log('\nЭзэмшигч бүртгэх — QPay мэдээллийг шифрлэж хадгална.\n');

const ownerName = await ask('Байгууллагын нэр            : ');
const contactPhone = await ask('Холбоо барих утас (8 орон) : ');
const deviceNo = await ask('Машины дугаар (deviceNo)   : ');
const location = await ask('Байршил                    : ', { required: false });
console.log('');
const username = await ask('QPay нэвтрэх нэр           : ');
const password = await askSecret('QPay нууц үг               : ');
const invoiceCode = await ask('QPay invoice code          : ');
rl.close();

try {
  if (!password) throw new Error('MISSING_FIELD');

  const out = await registerOwner({
    ownerName,
    contactPhone,
    deviceNo,
    location,
    username,
    password,
    invoiceCode,
  });

  console.log('\n✓ Бүртгэгдлээ');
  console.log(`  owner_id      ${out.ownerId}`);
  console.log(`  credential_id ${out.credentialId}`);
  console.log(`  machine_id    ${out.machineId}`);
  console.log(`  device_no     ${out.deviceNo}`);
  console.log('\nМашины notify_url нь эхний getQrCode хүсэлтээр өөрөө тогтоно.\n');
} catch (err) {
  const messages = {
    MISSING_FIELD: 'Бүх талбарыг бөглөнө үү.',
    MERCHANT_ALREADY_REGISTERED: `Энэ QPay мерчант аль хэдийн "${err.ownerName}"-д бүртгэлтэй байна.`,
    DEVICE_ALREADY_REGISTERED: 'Энэ машины дугаар аль хэдийн бүртгэлтэй байна.',
  };
  // Postgres error messages can echo a parameter value on some constraint
  // violations, so an unrecognised failure prints its code, not its text.
  console.error(`\n${messages[err.message] ?? `Алдаа: ${err.code ?? ''} ${err.constraint ?? ''}`.trim()}`);
  process.exitCode = 1;
} finally {
  await close();
}
