"""
Generates scripts/repair/2026-10-mojibake.sql — see the header it writes.

Text pasted into Supabase through `pbcopy` without a UTF-8 locale arrived
as Mac Roman: every UTF-8 byte became one character ("Тест" -> "–¢–µ...").
This rebuilds the affected SQL as pure ASCII (non-ASCII as U&'' escapes) so
it survives any clipboard. Run: python3 scripts/repair/make-mojibake-repair.py
"""
import glob, re

FUNCS = ['operator_provision_owner', 'operator_problems', 'owner_problems', 'accept_owner_invite',
         'credential_verify_budget', 'operator_owners', 'claim_invites_by_phone']
TEST_OWNER = "'7e570000-0000-4000-8000-000000000001'"


def lit(s):
    """A Postgres string literal for s using only ASCII."""
    if all(ord(c) < 128 for c in s):
        return "'" + s.replace("'", "''") + "'"
    out = []
    for c in s:
        if c == "'":
            out.append("''")
        elif c == '\\':
            out.append('\\\\')
        elif ord(c) < 128:
            out.append(c)
        elif ord(c) <= 0xFFFF:
            out.append('\\%04X' % ord(c))
        else:
            out.append('\\+%06X' % ord(c))
    return "U&'" + ''.join(out) + "'"


ASCII_FOR = {'—': '-', '–': '-', '·': '*', '→': '->', '«': '"', '»': '"', '‘': "'", '’': "'", '“': '"', '”': '"', '…': '...'}


def ascii_sql(text):
    """SQL rewritten as pure ASCII: string literals as U&'', comments transliterated."""
    res, i, n = [], 0, len(text)
    while i < n:
        if text.startswith('--', i):
            j = text.find('\n', i)
            j = n if j < 0 else j
            res.append(''.join(ASCII_FOR.get(ch, ch if ord(ch) < 128 else '?') for ch in text[i:j]))
            i = j
            continue
        c = text[i]
        if c == "'" and not (i > 0 and (text[i - 1].isalnum() or text[i - 1] in '&_')):
            j = i + 1
            while True:
                k = text.find("'", j)
                if k < 0:
                    raise ValueError('unterminated literal near: ' + text[i:i + 60])
                if k + 1 < n and text[k + 1] == "'":
                    j = k + 2
                    continue
                break
            res.append(lit(text[i + 1:k].replace("''", "'")))
            i = k + 1
            continue
        if ord(c) >= 128:
            raise ValueError('non-ASCII outside a literal/comment: %r near %r' % (c, text[max(0, i - 30):i + 30]))
        res.append(c)
        i += 1
    return ''.join(res)


def latest_def(name):
    """The last CREATE OR REPLACE of app.<name> across the migrations, verbatim."""
    found = None
    for f in sorted(glob.glob('migrations/0*.sql')):
        s = open(f, encoding='utf-8').read()
        for m in re.finditer(r'create or replace function app\.' + name + r'\s*\(', s):
            tail = s[m.start():]
            t = re.search(r'\bas\s+(\$[A-Za-z_]*\$)', tail)
            end = tail.find(t.group(1) + ';', t.end())
            found = (f, tail[:end + len(t.group(1)) + 1])
    if not found:
        raise SystemExit('no definition for app.' + name)
    return found


def mojibake(s):
    return s.encode('utf-8').decode('mac_roman')


parts = []
for fn in FUNCS:
    f, body = latest_def(fn)
    parts.append('-- app.%s, as in %s\n%s\n' % (fn, f, ascii_sql(body)))

updates = []


def fix(table, col, good, scope):
    updates.append('update public.%s set %s = %s where %s = %s and %s;' % (table, col, lit(good), col, lit(mojibake(good)), scope))


# Credential labels written by the corrupted provisioning function (any owner).
fix('qpay_credentials', 'label', 'Үндсэн данс', 'true')
# The test owner's rows, in case they are still there (scripts/seed/test-owner.sql).
T = 'id = ' + TEST_OWNER
O = 'owner_id = ' + TEST_OWNER
fix('owners', 'name', 'Туршилтын Кофе ХХК (тест)', T)
fix('owners', 'notes', 'TEST-SEED: туршилтын өгөгдөл. Устгах: scripts/seed/test-owner-cleanup.sql', T)
fix('qpay_credentials', 'label', 'Үндсэн', O)
fix('qpay_credentials', 'username_hint', 'test••••', O)
for v in ['Төв оффис', 'Их сургууль', 'Эмнэлэг']:
    fix('machines', 'label', v, O)
for v in ['СБД, Тест төв оффис, 1-р давхар', 'СХД, Тест их сургууль, хоолны танхим', 'БЗД, Тест эмнэлэг, хүлээлгийн танхим']:
    fix('machines', 'location', v, O)
for v in ['Латте', 'Американо', 'Каппучино', 'Халуун шоколад', 'Эспрессо', 'Цай', 'Какао']:
    fix('orders', 'product_name', v, O)
for v in ['TEST: QR үүсгэж чадсангүй', 'TEST: төлбөр орсон, машин хариу өгөөгүй']:
    fix('orders', 'last_error', v, O)

def src_has(fn, text):
    """The function's stored source holds `text` the way this file writes it
    (U&'' escapes), and no longer holds its Mac Roman corruption."""
    esc = lit(text)[3:-1] if lit(text).startswith("U&'") else text
    src = ("(select prosrc from pg_proc p join pg_namespace n on n.oid = p.pronamespace "
           "where n.nspname = 'app' and p.proname = '%s')" % fn)
    return "(position('%s' in %s) > 0 and position(%s in %s) = 0)" % (esc, src, lit(mojibake(text)), src)


check = """select
  (select count(*) from public.qpay_credentials where label = %s) = 0 as labels_ok,
  %s as operator_problems_ok,
  %s as provision_ok,
  %s as owner_problems_ok;""" % (
    lit(mojibake('Үндсэн данс')),
    src_has('operator_problems', 'мөнгө авсан'),
    src_has('operator_provision_owner', 'Үндсэн данс'),
    src_has('owner_problems', ' · '))

sql = """-- =====================================================================
-- Repair, 2026-10: text pasted into Supabase through `pbcopy` without a
-- UTF-8 locale arrived as Mac Roman (each UTF-8 byte became one character).
-- Generated by scripts/repair/make-mojibake-repair.py. This file is pure
-- ASCII on purpose (non-ASCII as U&'' escapes), so it survives any clipboard.
--
--   1. Re-creates the functions whose bodies held non-ASCII text, from the
--      migrations: the same definitions; CREATE OR REPLACE keeps grants.
--   2. Rewrites stored text the corrupted code wrote: credential labels
--      (the provisioning function's default label), and the test owner's
--      rows if they still exist.
--
-- Safe to re-run: each UPDATE matches only the corrupted value. The last
-- query should print four "true".
-- =====================================================================
begin;

""" + '\n'.join(parts) + '\n-- ---- stored text ----\n' + '\n'.join(updates) + '\n\n' + check + '\n\ncommit;\n'

assert all(ord(c) < 128 for c in sql), 'not pure ASCII'
open('scripts/repair/2026-10-mojibake.sql', 'w', encoding='ascii').write(sql)
print('written scripts/repair/2026-10-mojibake.sql:', len(sql), 'bytes,', len(parts), 'functions,', len(updates), 'updates')
