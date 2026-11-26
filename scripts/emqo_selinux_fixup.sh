#!/usr/bin/env bash
# Emqo android14-6.1.138 / SukiSU-Nova SELinux side-channel fixups.
# Runs after the main SUSFS patch and before defconfig/build.
set -euo pipefail

: "${KERNEL_ROOT:?KERNEL_ROOT is required}"

KSU_ROOT="$KERNEL_ROOT/KernelSU"
COMMON="$KERNEL_ROOT/common"
HIDE_C="$KSU_ROOT/kernel/feature/selinux_hide.c"
RULES_C="$KSU_ROOT/kernel/selinux/rules.c"
SELINUX_H="$KSU_ROOT/kernel/selinux/selinux.h"
SELINUX_C="$KSU_ROOT/kernel/selinux/selinux.c"
ALLOWLIST_H="$KSU_ROOT/kernel/policy/allowlist.h"

fail() { echo "::error::Emqo SELinux fixup: $*"; exit 1; }
for f in "$HIDE_C" "$RULES_C" "$SELINUX_H" "$SELINUX_C" "$ALLOWLIST_H"; do
  [ -f "$f" ] || fail "missing target file: $f"
done

# If a SUSFS patch removed one of the upstream hide entry points, restore the
# exact SukiSU source file from the pinned checkout before applying compatibility
# edits. The final assertions below refuse a partial restore.
for symbol in my_write_context my_write_access my_setprocattr; do
  if ! grep -qF "$symbol" "$HIDE_C"; then
    echo "[Emqo fixup] restoring $HIDE_C from pinned SukiSU checkout"
    git -C "$KSU_ROOT" show HEAD:kernel/feature/selinux_hide.c > "$HIDE_C" \
      || fail "cannot restore $HIDE_C from KernelSU HEAD"
    break
  fi
done

python3 - "$HIDE_C" "$RULES_C" <<'PY'
from pathlib import Path
import re
import sys

hide = Path(sys.argv[1])
rules = Path(sys.argv[2])
h = hide.read_text()
r = rules.read_text()

# Align the access response with the status page policy generation. The
# upstream SukiSU #3877-era code hard-coded avd.seqno=1, which creates the
# exact status/access split Maple probes after runtime policy publication.
if 'avd.seqno = status->policyload' not in h:
    block = '''    {
        struct page *spage = selinux_kernel_status_page();
        if (spage) {
            struct selinux_kernel_status *status = page_address(spage);
            if (status->policyload > 0)
                avd.seqno = status->policyload;
        }
    }
'''
    h2, count = re.subn(
        r'(?m)^(?P<i>[ \t]*)avd\.seqno[ \t]*=[ \t]*1;[ \t]*$',
        lambda m: m.group('i') + block.lstrip(),
        h,
        count=1,
    )
    if count != 1:
        raise SystemExit('cannot find the active avd.seqno=1 assignment')
    h = h2

# Disable only the status-page policyload publication calls. Keep
# pol->latest_granting = old_pol->latest_granting + 1 intact; that is the
# correct generation bookkeeping used by the policy object itself.
new_lines = []
for line in r.splitlines(True):
    stripped = line.lstrip()
    if 'policydb->latest_granting = old_pol->latest_granting + 1;' in line:
        line = line.replace('policydb->latest_granting = old_pol->latest_granting + 1;',
                            'pol->latest_granting = old_pol->latest_granting + 1;')
    if 'selinux_status_update_policyload(' in line and not stripped.startswith('//'):
        indent = line[:len(line) - len(stripped)]
        line = indent + '// Emqo Maple seqno fix: ' + stripped
    new_lines.append(line)
r = ''.join(new_lines)

# Prevent a later policy publication from overwriting the original backup
# policy used by selinux_hide validation.
if 'if (!backup_sepolicy)' not in r:
    lines = r.splitlines(True)
    start = next((i for i, line in enumerate(lines)
                  if 'backup_sepolicy = ksu_dup_sepolicy(' in line), None)
    end = next((i for i, line in enumerate(lines[start + 1:], start + 1)
                if 'pol = ksu_dup_sepolicy(' in line), None) if start is not None else None
    if start is None or end is None:
        raise SystemExit('cannot locate backup_sepolicy initialization block')
    lines.insert(start, '    if (!backup_sepolicy) {\n')
    end += 1
    lines.insert(end, '    }\n')
    r = ''.join(lines)

hide.write_text(h)
rules.write_text(r)
PY

# Add app_zygote as a zygote-equivalent context for hide decisions. The UID
# range is already present in newer Emqo allowlist.h; assert it below.
python3 - "$SELINUX_H" "$SELINUX_C" <<'PY'
from pathlib import Path
import sys

header = Path(sys.argv[1])
source = Path(sys.argv[2])
h = header.read_text()
c = source.read_text()

if 'APP_ZYGOTE_CONTEXT' not in h:
    anchor = '#define ZYGOTE_CONTEXT "u:r:zygote:s0"'
    if anchor not in h:
        raise SystemExit('cannot locate ZYGOTE_CONTEXT in selinux.h')
    h = h.replace(anchor, anchor + '\n#define APP_ZYGOTE_CONTEXT "u:r:app_zygote:s0"', 1)

if 'cached_app_zygote_sid' not in c:
    anchor = 'static u32 cached_zygote_sid __read_mostly = 0;'
    if anchor not in c:
        raise SystemExit('cannot locate cached_zygote_sid in selinux.c')
    c = c.replace(anchor, anchor + '\nstatic u32 cached_app_zygote_sid __read_mostly = 0;', 1)

if 'security_secctx_to_secid(APP_ZYGOTE_CONTEXT' not in c:
    anchor = '    err = security_secctx_to_secid(INIT_CONTEXT, strlen(INIT_CONTEXT), &cached_init_sid);'
    if anchor not in c:
        raise SystemExit('cannot locate INIT_CONTEXT SID cache in selinux.c')
    block = '''    err = security_secctx_to_secid(APP_ZYGOTE_CONTEXT, strlen(APP_ZYGOTE_CONTEXT), &cached_app_zygote_sid);
    if (err) {
        pr_warn("Failed to cache app_zygote SID: %d\\n", err);
        cached_app_zygote_sid = 0;
    } else {
        pr_info("Cached app_zygote SID: %u\\n", cached_app_zygote_sid);
    }

'''
    c = c.replace(anchor, block + anchor, 1)

old = 'return is_sid_match(cred, cached_zygote_sid, ZYGOTE_CONTEXT);'
new = 'return is_sid_match(cred, cached_zygote_sid, ZYGOTE_CONTEXT) || is_sid_match(cred, cached_app_zygote_sid, APP_ZYGOTE_CONTEXT);'
if old in c and new not in c:
    c = c.replace(old, new, 1)

header.write_text(h)
source.write_text(c)
PY

# Hard assertions are intentionally inside the fixup itself as well as the
# workflow step, so a direct local invocation cannot silently produce a weak build.
for symbol in my_write_context my_write_access my_setprocattr; do
  grep -qF "$symbol" "$HIDE_C" || fail "missing hide hook symbol: $symbol"
done
grep -qF 'avd.seqno = status->policyload' "$HIDE_C" || fail 'seqno alignment was not applied'
if grep -qE '^[[:space:]]*avd\.seqno[[:space:]]*=[[:space:]]*1;' "$HIDE_C"; then
  fail 'active hard-coded avd.seqno=1 remains'
fi
if grep -qE '^[[:space:]]*[^[:space:]/].*selinux_status_update_policyload\(' "$RULES_C"; then
  fail 'active selinux_status_update_policyload call remains'
fi
grep -qF 'pol->latest_granting = old_pol->latest_granting + 1;' "$RULES_C" \
  || fail 'correct pol->latest_granting generation update is missing'
grep -qF 'APP_ZYGOTE_CONTEXT' "$SELINUX_H" \
  || fail 'APP_ZYGOTE_CONTEXT is missing'
grep -qF 'cached_app_zygote_sid' "$SELINUX_C" \
  || fail 'app_zygote SID cache is missing'
grep -qF 'FIRST_APP_ZYGOTE_ISOLATED_UID 90000' "$ALLOWLIST_H" \
  || fail 'app_zygote UID lower bound is missing'
grep -qF 'LAST_APP_ZYGOTE_ISOLATED_UID 98999' "$ALLOWLIST_H" \
  || fail 'app_zygote UID upper bound is missing'
grep -RqsE 'susfs_selinux_inode_setxattr|handle_selinux_inode_setxattr' "$COMMON" \
  || fail 'SUSFS f76b81f inode_setxattr hook is missing from common/'

echo '[Emqo fixup] all SELinux/app_zygote/inode_setxattr assertions passed'
