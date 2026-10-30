#!/usr/bin/env python3
"""Normalized v4/v6 diff for the eBPF C sources in pkg/ebpf/c.

Usage:
  v4v6-diff.py <v4 file> <v6 file>    diff one pair of files
  v4v6-diff.py --funcs <file>         diff each foo_v4 / foo_v6 function pair
                                      defined in one file (shared headers)
  v4v6-diff.py --all [<repo root>]    the three file pairs, then --funcs on
                                      every pkg/ebpf/c/*.h except vmlinux.h
                                      (default root: .)
  add --no-lines to drop line numbers, so two runs can be diffed

The script strips comments and whitespace and rewrites address-family tokens
to a common form (address types and field names, IP header type, L4 protocol
field, EtherType, IP version, host prefix length, port width, and a _v4 / _v6
suffix on any identifier). The trie key fill (four byte assignments in v4, a
16-byte loop in v6) collapses to one token only when it has exactly the
expected shape; otherwise its lines are kept and compared like any other. No
source line is dropped. It then diffs the two token streams. Each hunk prints
"v4:<lines> | v6:<lines>" so it points back at the original source.

In --funcs mode a function is a definition whose name ends in _v4 or _v6.
A function without its twin is reported as "unpaired". Files with no such
functions print nothing.

Known noise: a reordered statement shows up as a paired insert and delete of
the same text, and a lone "}" can be aligned into a neighboring hunk.

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
    (r'\b(\w+)_v[46]\b', r'\1_vX'),                    # family-suffixed names
    (r'\s+', ' '),
]
V4 = [
    (r'__u32 (src_ip|dest_ip|owner_ip)\b', r'ADDR \1'),
    (r'__u8 ip\[4\]', 'IPBYTES ip'),
    (r'__u32 ip;', 'IPBYTES ip;'),
    (r'evt\.(src|dest)_ip = flow_key\.(src|dest)_ip;',
     lambda m: 'evt.%s_ip = ip->%saddr;' % (m.group(1), m.group(1)[0])),
    (r'prefix_len = 32', 'prefix_len = PLEN'),
    (r'0x08U', 'ETH_P'),
    (r'version != 4', 'version != VER'),
    (r'struct iphdr', 'struct IPHDR'),
    (r'ip->protocol', 'ip->L4PROTO'),
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

PAIRS = [
    ('tc.v4ingress.bpf.c', 'tc.v6ingress.bpf.c'),
    ('tc.v4egress.bpf.c', 'tc.v6egress.bpf.c'),
    ('v4events.bpf.c', 'v6events.bpf.c'),
]

# Start of a function definition whose name ends in _v4 or _v6.
FUNC_START = re.compile(r'^[A-Za-z_][\w\s\*]*?\b(\w+)_v([46])\s*\(')


def strip_comments(text):
    # Keep newlines inside block comments so line numbers stay correct.
    text = re.sub(r'/\*.*?\*/', lambda m: '\n' * m.group(0).count('\n'), text, flags=re.S)
    return [re.sub(r'//.*', '', line) for line in text.split('\n')]


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


def norm(path, rules, blocks):
    with open(path) as f:
        lines = strip_comments(f.read())
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


def diff_pair(v4_path, v6_path, lines=True):
    diff_items(norm(v4_path, V4, V4_BLOCKS), norm(v6_path, V6, V6_BLOCKS), lines)


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
    args = [a for a in argv if a != '--no-lines']
    if args and args[0] == '--all':
        root = args[1] if len(args) > 1 else '.'
        cdir = os.path.join(root, 'pkg', 'ebpf', 'c')
        for v4_name, v6_name in PAIRS:
            print('#### %s vs %s' % (v4_name, v6_name))
            diff_pair(os.path.join(cdir, v4_name), os.path.join(cdir, v6_name), lines)
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
    diff_pair(args[0], args[1], lines)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
