#!/usr/bin/env python3
"""Normalized v4/v6 diff for the eBPF C sources in pkg/ebpf/c.

Usage:
  v4v6-diff.py [-D<macro>] <v4 file> <v6 file>
                                      diff one pair of files, as built with
                                      the given variant macro (see below)
  v4v6-diff.py --funcs <file>         diff each foo_v4 / foo_v6 function pair
                                      defined in one file (shared headers)
  v4v6-diff.py --all [<repo root>]    every object pair the Makefile builds
                                      (regular ingress, ct-deny ingress,
                                      egress, events), then --funcs on every
                                      pkg/ebpf/c/*.h except vmlinux.h
                                      (default root: .)
  add --no-lines to drop line numbers, so two runs can be diffed

Variant macros: the ct-deny ingress objects (tc.v4ingress.ctdeny.bpf.o,
tc.v6ingress.ctdeny.bpf.o) are built from the regular ingress sources with
-DNPA_CT_SHORTEN_ON_DENY. For each file pair the script resolves
#ifdef / #ifndef / #else / #endif on VARIANT_MACROS as that object's build
does, so each pair is diffed as compiled. Lines a build drops are blanked, so
line numbers still point at the source. Other preprocessor lines are kept and
compared as text. Without -D, pair mode diffs the regular objects. --funcs
does not resolve macros.

The script strips comments and whitespace and rewrites address-family tokens
to a common form (address types and field names, IP header type, L4 protocol
field, EtherType, IP version, host prefix length, port width, and the
family's own suffix, _v4 in v4 files and _v6 in v6 files, on any identifier).
A _v6 name in a v4 file, or a _v4 name in a v6 file, is left as is and shows as
a hunk. The trie key fill (four byte assignments in v4, a
16-byte loop in v6) collapses to one token only when it has exactly the
expected shape; otherwise its lines are kept and compared like any other. No
source line is dropped. It then diffs the two token streams. Each hunk prints
"v4:<lines> | v6:<lines>" so it points back at the original source.

In --funcs mode a function is a definition whose name ends in _v4 or _v6.
A function without its twin is reported as "unpaired". Files with no such
functions print nothing.

Known noise: a reordered statement shows up as a paired insert and delete of
the same text, and a lone "}" can be aligned into a neighboring hunk.

What the rewrites hide, so check these by reading:
  - ip->protocol (v4) and ip->nexthdr (v6) both become ip->L4PROTO. In v6 the
    next header can be an extension header, not TCP or UDP. How the v6 code
    handles extension headers behind nexthdr is not compared.
  - __u16 and __u32 l4_src_port / l4_dst_port both become __uXX, so a change
    of port width in either family does not show.
  - --funcs finds a definition only when it starts in column 0 with the name
    on the same line as the return type, for example
    "static __always_inline void foo_v4(". A definition written with the name
    on the next line is skipped. Each name is kept once per family, so a
    second definition of the same name (for example in an #ifdef / #else
    branch, which --funcs does not resolve) replaces the first.

Diff the diff on a change (BASE = merge base checkout, HEAD = change checkout):
  diff <(python3 -I hack/v4v6-diff.py --all --no-lines "$BASE") \\
       <(python3 -I hack/v4v6-diff.py --all --no-lines "$HEAD")
"""
import difflib
import glob
import os
import re
import sys

PRE = [  # applied to both families, before the family rules
    (r'\s+', ' '),
    (r' ,', ','),
    (r' ?(?<![=!<>])=(?!=) ?', ' = '),
]
COMMON = [  # applied to both families, after the family rules
    (r'\(struct conntrack_value \*\)', ''),           # v6 casts the lookup result
    (r'__u(16|32) (l4_(src|dst)_port)', r'__uXX \2'),  # port local width differs
    (r'\s+', ' '),
]
V4 = [
    (r'__u32 (src_ip|dest_ip|owner_ip)\b', r'ADDR \1'),
    (r'__u8 ip\[4\]', 'IPBYTES ip'),
    (r'__u32 ip;', 'IPBYTES ip;'),
    (r'evt\.(src|dest)_ip = flow_key\.(src|dest)_ip;',
     lambda m: 'evt.%s_ip = ip->%saddr;' % (m.group(1), m.group(2)[0])),
    (r'prefix_len = 32', 'prefix_len = PLEN'),
    (r'0x08U', 'ETH_P'),
    (r'version != 4', 'version != VER'),
    (r'struct iphdr', 'struct IPHDR'),
    (r'ip->protocol', 'ip->L4PROTO'),
    # Only this family's suffix is rewritten, so a call to the other family's
    # helper (shorten_denied_syn_v6 in a v4 file) survives and shows as a hunk.
    (r'\b(\w+)_v4\b', r'\1_vX'),
]
V6 = [
    (r'struct\s+in6_addr\s+saddr', 'ADDR src_ip'),
    (r'struct\s+in6_addr\s+daddr', 'ADDR dest_ip'),
    (r'struct\s+in6_addr\s+owner_addr', 'ADDR owner_ip'),
    (r'struct\s+in6_addr\s+(src_ip|dest_ip)', r'ADDR \1'),
    (r'__u8\s+(src_ip|dest_ip)\[16\]', r'ADDR \1'),      # v6events.bpf.c data_t
    (r'__u8\s+ip\[16\]', 'IPBYTES ip'),
    (r'(flow_key|reverse_flow_key)\.saddr', r'\1.src_ip'),
    (r'(flow_key|reverse_flow_key)\.daddr', r'\1.dest_ip'),
    (r'owner_addr', 'owner_ip'),
    (r'prefix_len = 128', 'prefix_len = PLEN'),
    (r'0xdd86', 'ETH_P'),
    (r'version != 6', 'version != VER'),
    (r'struct ipv6hdr', 'struct IPHDR'),
    (r'ip->nexthdr', 'ip->L4PROTO'),
    (r'\b(\w+)_v6\b', r'\1_vX'),
]

# Trie key fill blocks. A block collapses to FILL_TRIE(<x>addr); only when
# every line has exactly this shape with the same address. Any other edit
# leaves the lines in place, so the diff reports it.
V4_BLOCKS = [[
    r'trie_key\.ip\[0\] = ip->(?P<a>[sd])addr & 0xff;',
    r'trie_key\.ip\[1\] = \(ip->(?P=a)addr >> 8\) & 0xff;',
    r'trie_key\.ip\[2\] = \(ip->(?P=a)addr >> 16\) & 0xff;',
    r'trie_key\.ip\[3\] = \(ip->(?P=a)addr >> 24\) & 0xff;',
]]
V6_BLOCKS = [[
    r'for \(int i = 0; i<16; i\+\+\)\{',
    r'trie_key\.ip\[i\] = ip->(?P<a>[sd])addr\.in6_u\.u6_addr8\[i\];',
    r'\}',
]]

# Macros that select a build variant. Defined only on the command lines in
# PAIRS; every other macro is left to the compiler.
VARIANT_MACROS = {'NPA_CT_SHORTEN_ON_DENY'}

# (v4 source, v6 source, macros defined for this object pair, label), one per
# object pair the Makefile build-bpf target builds.
PAIRS = [
    ('tc.v4ingress.bpf.c', 'tc.v6ingress.bpf.c', set(), ''),
    ('tc.v4ingress.bpf.c', 'tc.v6ingress.bpf.c', {'NPA_CT_SHORTEN_ON_DENY'},
     ' -DNPA_CT_SHORTEN_ON_DENY (tc.v4ingress.ctdeny.bpf.o vs tc.v6ingress.ctdeny.bpf.o)'),
    ('tc.v4egress.bpf.c', 'tc.v6egress.bpf.c', set(), ''),
    ('v4events.bpf.c', 'v6events.bpf.c', set(), ''),
]

COND = re.compile(r'^\s*#\s*(ifdef|ifndef|if|else|elif|endif)\b\s*(\w*)')

# Start of a function definition whose name ends in _v4 or _v6.
FUNC_START = re.compile(r'^[A-Za-z_][\w\s\*]*?\b(\w+)_v([46])\s*\(')


def strip_comments(text):
    # Keep newlines inside block comments so line numbers stay correct.
    text = re.sub(r'/\*.*?\*/', lambda m: '\n' * m.group(0).count('\n'), text, flags=re.S)
    return [re.sub(r'//.*', '', line) for line in text.split('\n')]


def resolve_variants(lines, defined):
    """Blank the lines a build with `defined` drops, and the directives on
    VARIANT_MACROS. Conditionals on other macros are kept as text."""
    out, stack = [], []  # stack entries: (tracked, keeping this branch)
    for line in lines:
        m = COND.match(line)
        keep = all(k for _, k in stack)
        if m:
            kind, name = m.groups()
            if kind in ('ifdef', 'ifndef', 'if'):
                tracked = kind != 'if' and name in VARIANT_MACROS
                taken = (name in defined) == (kind == 'ifdef') if tracked else True
                stack.append((tracked, taken))
                out.append('' if tracked or not keep else line)
                continue
            tracked = bool(stack) and stack[-1][0]
            if kind == 'endif':
                if stack:
                    stack.pop()
            elif tracked:
                if kind == 'elif':
                    sys.exit('#elif inside a variant conditional is not handled')
                stack[-1] = (True, not stack[-1][1])
            out.append('' if tracked or not keep else line)
            continue
        out.append(line if keep else '')
    return out


def collapse(items, blocks):
    out, i = [], 0
    while i < len(items):
        for block in blocks:
            text = '\n'.join(t for _, t in items[i:i + len(block)])
            m = re.fullmatch('\n'.join(block), text)
            if m:
                out.append((items[i][0], 'FILL_TRIE(%saddr);' % m.group('a')))
                i += len(block)
                break
        else:
            out.append(items[i])
            i += 1
    return out


def norm_lines(numbered, rules, blocks):
    out = []
    for n, line in numbered:
        for pat, rep in PRE + rules + COMMON:
            line = re.sub(pat, rep, line)
        line = line.strip()
        if line:
            out.append((n, line))
    return collapse(out, blocks)


def norm(path, rules, blocks, defined=frozenset()):
    with open(path) as f:
        lines = resolve_variants(strip_comments(f.read()), defined)
    return norm_lines(enumerate(lines, 1), rules, blocks)


def rng(items, a, b):
    if a == b:
        return '(none)'
    if b - a > 1:
        return '%d-%d' % (items[a][0], items[b - 1][0])
    return str(items[a][0])


def diff_items(v4, v6, lines):
    sm = difflib.SequenceMatcher(a=[t for _, t in v4], b=[t for _, t in v6], autojunk=False)
    for tag, a1, a2, b1, b2 in sm.get_opcodes():
        if tag == 'equal':
            continue
        if lines:
            print('== %s  v4:%s | v6:%s' % (tag, rng(v4, a1, a2), rng(v6, b1, b2)))
        else:
            print('== %s' % tag)
        for n, t in v4[a1:a2]:
            print('  - v4:%-4d %s' % (n, t) if lines else '  - %s' % t)
        for n, t in v6[b1:b2]:
            print('  + v6:%-4d %s' % (n, t) if lines else '  + %s' % t)


def diff_pair(v4_path, v6_path, lines=True, defined=frozenset()):
    diff_items(norm(v4_path, V4, V4_BLOCKS, defined),
               norm(v6_path, V6, V6_BLOCKS, defined), lines)


def find_funcs(path):
    """Return {(base, family): [(line_no, text), ...]} for _v4/_v6 definitions."""
    with open(path) as f:
        lines = strip_comments(f.read())
    funcs, i = {}, 0
    while i < len(lines):
        m = FUNC_START.match(lines[i])
        if not m:
            i += 1
            continue
        # Read up to the first '{' or ';' (a prototype), then to the matching '}'.
        body, depth, opened, j = [], 0, False, i
        while j < len(lines):
            line = lines[j]
            body.append((j + 1, line))
            if not opened and ';' in line and '{' not in line:
                break
            for ch in line:
                if ch == '{':
                    depth += 1
                    opened = True
                elif ch == '}':
                    depth -= 1
            if opened and depth == 0:
                break
            j += 1
        if opened:
            funcs[(m.group(1), m.group(2))] = body
        i = j + 1
    return funcs


def diff_funcs(path, lines=True):
    funcs = find_funcs(path)
    if not funcs:
        return
    print('#### %s _v4/_v6 functions' % os.path.basename(path))
    for base in sorted({b for b, _ in funcs}):
        v4, v6 = funcs.get((base, '4')), funcs.get((base, '6'))
        if v4 is None or v6 is None:
            fam, body = ('v4', v4) if v6 is None else ('v6', v6)
            where = ':%d' % body[0][0] if lines else ''
            print('== unpaired %s %s_%s%s' % (fam, base, fam, where))
            continue
        print('### %s_v4 vs %s_v6' % (base, base))
        diff_items(norm_lines(v4, V4, V4_BLOCKS), norm_lines(v6, V6, V6_BLOCKS), lines)


def main(argv):
    lines = '--no-lines' not in argv
    defined = {a[2:] for a in argv if a.startswith('-D')}
    unknown = defined - VARIANT_MACROS
    if unknown:
        print('not a variant macro: %s' % ', '.join(sorted(unknown)), file=sys.stderr)
        return 2
    args = [a for a in argv if a != '--no-lines' and not a.startswith('-D')]
    if args and args[0] == '--all':
        root = args[1] if len(args) > 1 else '.'
        cdir = os.path.join(root, 'pkg', 'ebpf', 'c')
        for v4_name, v6_name, pair_defined, label in PAIRS:
            print('#### %s vs %s%s' % (v4_name, v6_name, label))
            diff_pair(os.path.join(cdir, v4_name), os.path.join(cdir, v6_name), lines,
                      pair_defined)
        for header in sorted(glob.glob(os.path.join(cdir, '*.h'))):
            if os.path.basename(header) != 'vmlinux.h':
                diff_funcs(header, lines)
        return 0
    if len(args) == 2 and args[0] == '--funcs':
        diff_funcs(args[1], lines)
        return 0
    if len(args) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    diff_pair(args[0], args[1], lines, defined)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
