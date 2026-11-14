-- =====================================================================
-- 020 — the house merchant (OPERATOR_MERCHANT_OWNER_ID)
--
-- The operator's money — the system subscription (019) and every sale on a
-- machine nobody has registered — moves from the env QPAY_* account to one
-- business's own connected QPay account, named by the bridge's
-- OPERATOR_MERCHANT_OWNER_ID. Nothing here names that business: the id
-- lives in the bridge's environment, not in this public repository.
--
-- Each billing invoice now records the account that issued it, so one made
-- before the switch is still checked — and credited — through the account
-- that made it, and the billing page shows only invoices of the account
-- that takes payments now.
--
-- Orders need no new column: an unregistered machine's order is an env row
-- whose merchant_fp (018) has been null so far; the house writes its marker
-- there.
--
-- Idempotent; safe to run twice.
-- =====================================================================
begin;

alter table public.billing_invoices add column if not exists merchant text;

do $$ begin
  if not exists (select 1 from pg_constraint where conname = 'billing_invoices_merchant_shape') then
    alter table public.billing_invoices add constraint billing_invoices_merchant_shape
      check (merchant is null or merchant ~ '^house:[0-9a-f-]{36}:[0-9a-f]{64}$');
  end if;
end $$;

comment on column public.billing_invoices.merchant is
  'The QPay account that issued the invoice: NULL = the env QPAY_* account; house:<credential id>:<fingerprint> = that business credential (OPERATOR_MERCHANT_OWNER_ID). Checks go to the issuer.';
comment on column public.orders.merchant_fp is
  'Owner rows: the credential fingerprint when the invoice was made. Env rows: NULL = the env QPAY_* account; house:<credential id>:<fingerprint> = the house credential that issued it.';

commit;
