import webpush from 'web-push';
import * as store from './store.js';

/**
 * Web Push to the portal installed on an owner's phone (migration 017).
 *
 * Two senders use it: a sale, the moment its money is confirmed, and the
 * operator's announcements. Both are best-effort and run after the thing they
 * report has already happened, so nothing here throws into a caller — a push
 * that fails costs a notification, never a coffee or an announcement record.
 *
 * Off unless VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY and VAPID_SUBJECT are all
 * set. The public key is also what the portal subscribes with
 * (GET /owner/v1/push/key), so rotating it here re-keys both ends at once —
 * and quietly orphans every existing subscription, which is why it is not
 * rotated.
 */

const PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY ?? '';
const PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY ?? '';
const SUBJECT = process.env.VAPID_SUBJECT ?? '';

export const pushConfigured = () => Boolean(PUBLIC_KEY && PRIVATE_KEY && SUBJECT);
export const publicKey = () => (pushConfigured() ? PUBLIC_KEY : null);

let vapidSet = false;
function configure() {
  if (!vapidSet) {
    webpush.setVapidDetails(SUBJECT, PUBLIC_KEY, PRIVATE_KEY);
    vapidSet = true;
  }
}

/*
 * The bridge POSTs to whatever endpoint a signed-in browser handed it, so the
 * endpoint is an SSRF surface exactly like a machine's notifyUrl. Only the
 * push services browsers actually use are accepted. PUSH_ALLOW_HOSTS adds to
 * the list (the test suite's local push service), it never replaces it.
 */
const PUSH_HOSTS = [
  'fcm.googleapis.com',
  'android.googleapis.com',
  'updates.push.services.mozilla.com',
  'push.services.mozilla.com',
  'web.push.apple.com',
  'notify.windows.com',
  ...(process.env.PUSH_ALLOW_HOSTS ?? '').split(',').map((h) => h.trim()).filter(Boolean),
];

export function endpointAllowed(raw) {
  let url;
  try {
    url = new URL(String(raw));
  } catch {
    return false;
  }
  if (url.protocol !== 'https:') return false;
  return PUSH_HOSTS.some((h) => url.hostname === h || url.hostname.endsWith(`.${h}`));
}

const hostOf = (endpoint) => {
  try {
    return new URL(endpoint).host;
  } catch {
    return '?';
  }
};

/**
 * Sends one payload to each subscription. 404/410 is the push service saying
 * the browser unsubscribed; those rows are deleted rather than retried on
 * every sale forever. Logs carry the endpoint's host only — the full endpoint
 * is a capability to push to that phone.
 */
async function deliver(subs, payload, log) {
  if (!subs.length) return { sent: 0, failed: 0 };
  configure();
  const body = JSON.stringify(payload);
  const results = await Promise.allSettled(
    subs.map((s) =>
      webpush.sendNotification({ endpoint: s.endpoint, keys: { p256dh: s.p256dh, auth: s.auth } }, body, {
        TTL: 6 * 3600,
        urgency: 'high',
        timeout: 8000,
      })
    )
  );
  const okIds = [];
  const goneIds = [];
  let failed = 0;
  results.forEach((r, i) => {
    if (r.status === 'fulfilled') return okIds.push(subs[i].id);
    const code = r.reason?.statusCode;
    if (code === 404 || code === 410) return goneIds.push(subs[i].id);
    failed += 1;
    log('push failed', hostOf(subs[i].endpoint), code ?? String(r.reason?.message ?? r.reason).split('\n')[0]);
  });
  await store.pushDelivered({ okIds, goneIds }).catch((err) => log('push bookkeeping failed', err.message.split('\n')[0]));
  return { sent: okIds.length, failed };
}

const mnt = (n) => `${Math.round(Number(n) || 0).toLocaleString('en-US')}₮`;

/** «+5,900₮» on the lock screen, the moment a sale's money is confirmed. Once per order. */
export async function pushSale(orderId, log = () => {}) {
  if (!pushConfigured()) return;
  try {
    const sale = await store.claimSalePush(orderId);
    if (!sale) return;
    const subs = await store.saleSubscriptions(sale.owner_id);
    if (!subs.length) return;
    const where = `машин ${sale.device_no}${sale.place ? `, ${sale.place}` : ''}`;
    await deliver(
      subs,
      {
        title: `Орлого +${mnt(sale.amount_mnt)}`,
        body: sale.product_name ? `${sale.product_name} · ${where}` : where,
        url: '/sales',
        tag: `sale-${orderId}`,
      },
      log
    );
  } catch (err) {
    log('sale push failed', orderId, err.message.split('\n')[0]);
  }
}

/** An announcement to everyone who runs one of these businesses. */
export async function pushToOwners(ownerIds, payload, log = () => {}) {
  if (!pushConfigured() || !ownerIds.length) return { sent: 0, failed: 0 };
  try {
    return await deliver(await store.ownerSubscriptions(ownerIds), payload, log);
  } catch (err) {
    log('announcement push failed', err.message.split('\n')[0]);
    return { sent: 0, failed: 0 };
  }
}

/** The settings page's «Туршилтын мэдэгдэл»: every device of one person. */
export async function pushToUser(userId, payload, log = () => {}) {
  if (!pushConfigured()) return { sent: 0, failed: 0 };
  return deliver(await store.userSubscriptions(userId), payload, log);
}
