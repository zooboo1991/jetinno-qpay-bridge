import { randomUUID } from 'node:crypto';
import { query } from './db.js';
import {
  seal,
  credentialAad,
  activeKeyId,
  fingerprint,
  merchantIdentity,
} from './crypto.js';

/**
 * Registers an owner, their sealed QPay credential, and one machine.
 *
 * Split out of scripts/add-owner.js so it can be tested without inventing a
 * way to feed a password into the CLI non-interactively — a test-only input
 * path for a secret is exactly the kind of thing that survives into
 * production. The CLI collects input; this does the work.
 *
 * The plaintext password lives only in this function's arguments and inside
 * seal(). It is never logged, never returned, and never placed on an object
 * that a caller might serialise.
 */
export async function registerOwner({
  ownerName,
  contactPhone,
  deviceNo,
  location,
  username,
  password,
  invoiceCode,
}) {
  if (!ownerName || !contactPhone || !deviceNo || !username || !password || !invoiceCode) {
    throw new Error('MISSING_FIELD');
  }

  const ownerId = randomUUID();
  const credentialId = randomUUID();
  const machineId = randomUUID();

  const fp = fingerprint(merchantIdentity({ username, invoiceCode }));

  // Two owners pointing at one merchant means one of them is receiving the
  // other's money. Refuse here rather than let it surface from a bank
  // statement weeks later.
  const clash = await query(
    `select o.name
       from public.qpay_credentials c
       join public.owners o on o.id = c.owner_id
      where c.fingerprint = $1 or c.pending_fingerprint = $1`,
    [fp]
  );
  if (clash.rows.length) {
    const err = new Error('MERCHANT_ALREADY_REGISTERED');
    err.ownerName = clash.rows[0].name;
    throw err;
  }

  const existingDevice = await query(`select 1 from public.machines where device_no = $1`, [
    deviceNo,
  ]);
  if (existingDevice.rows.length) throw new Error('DEVICE_ALREADY_REGISTERED');

  const sealed = seal(
    { username, password, invoice_code: invoiceCode },
    // Binds both ids into the GCM tag: the blob cannot be moved to another
    // credential row or re-parented to another owner.
    { context: credentialAad({ credentialId, ownerId }) }
  );

  await query(
    `insert into public.owners (id, name, contact_phone, status) values ($1,$2,$3,'active')`,
    [ownerId, ownerName, contactPhone]
  );
  await query(
    `insert into public.qpay_credentials
       (id, owner_id, label, sealed, key_id, fingerprint, username_hint, invoice_code_hint,
        status, is_active, source, last_verified_at)
     values ($1,$2,$3,$4,$5,$6,$7,$8,'active',true,'cli',now())`,
    [
      credentialId,
      ownerId,
      'Үндсэн данс',
      sealed,
      activeKeyId(),
      fp,
      maskUsername(username),
      invoiceCode.slice(-4),
    ]
  );
  await query(
    // notify_url stays NULL: it is not known until the machine's first signed
    // getQrCode pins it, and an empty string would look like a pinned value.
    `insert into public.machines
       (id, owner_id, qpay_credential_id, device_no, label, location, notify_url, status)
     values ($1,$2,$3,$4,$5,$6,null,'active')`,
    [machineId, ownerId, credentialId, deviceNo, ownerName, location || null]
  );

  return { ownerId, credentialId, machineId, deviceNo };
}

export function maskUsername(username) {
  if (username.length <= 4) return '•'.repeat(username.length);
  return `${username.slice(0, 3)}${'•'.repeat(Math.max(username.length - 5, 3))}${username.slice(-2)}`;
}
