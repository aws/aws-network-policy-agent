#!/usr/bin/env python3
"""Check the `path:line` citations in a review guide against source trees.

Usage:
  check-guide-cites.py --npa <tree> --sdk <tree> [--sdk-main <tree>] <guide.md>

Each <tree> is a checkout at the commit the guide names (NPA 4bf96cf, SDK
v1.0.19 9127cb7, SDK main 62628d3). The trees are only read.

A cite is a backticked `file:N`, `file:N-M` or `file:N,M-K`, file being a repo
path or a suffix of one. A bare `:N` refers to the last file named under the
same heading (a cite or a backticked path such as `Makefile`), a bare `N-M` to
the last file in the paragraph, and in a table to a path named higher up in
the same column. Tree choice: a file in only NPA or only the SDK resolves
there, one in both follows the last "NPA" / "SDK <commit>:" marker. The SDK
tree follows the last "SDK main" / v1.0.17 / 9127cb7 marker (default v1.0.19).
v1.0.17 and other repos (netlink, zap, controller-runtime, VPC CNI, EKS AMI, Linux)
have no tree and are skipped.

Symbols are other backticked spans tied to the cite (in its parenthetical,
just before it, or right after it), else the clause's spans no other cite
owns. ok: one symbol's identifiers are all in the cited lines +-3, or it names
the enclosing function. moved: found elsewhere (nearest line shown). missing:
not in the file. backref: a bare cite that fails on the last-named file but is
ok on an earlier one. Exit 1 on missing, range, no-file or ambiguous.
"""
import argparse
import os
import re
import sys

SLACK = 3
RANGES = r'\d+(?:-\d+)?(?:\s*,\s*\d+(?:-\d+)?)*'
FILE = r'(?:[\w.-]+/)*(?:[\w-][\w.-]*\.(?:go|c|h|sh|ya?ml|mod|py|json)|Dockerfile|Makefile)'
CITE = re.compile(r'^(?P<file>%s)?:(?P<r>%s)$' % (FILE, RANGES))
BARE = re.compile(r'^(?P<r>%s)$' % RANGES)
PATH = re.compile(r'^%s$' % FILE)
SPAN = re.compile(r'`([^`\n]+)`')
SENTENCE_END = re.compile(r'[.!?](?=\s+[A-Z\[(*`])|\|')
CLAUSE_END = re.compile(r'[;|]|, (?:and|so|but|which) |: ')
UNIT_START = re.compile(r'^\s*([-*] |\d+\. |\|)')
TOKEN = re.compile(r'[A-Za-z_]\w*(?!\w*\.[A-Za-z_])')  # drops a pkg. qualifier
NOT_SYMBOL = re.compile(r'^(grep|git|python3|go |make|kubectl|cd |diff|sudo)|[/<]|^[0-9a-f]{7,40}$')
FAMILY = [(re.compile(r'\bNPA\b'), 'npa'),
          (re.compile(r'\bSDK (?:main|[0-9a-f]{7}|v1\.0\.\d+:)'), 'sdk'),
          (re.compile(r'netlink|\bzap `|controller-runtime|VPC CNI|amazon-vpc-cni-k8s|'
                      r'chart `|amazon-eks-ami|EKS AMI|Linux v?\d|kernel source'), 'ext')]
VERSION = [(re.compile(r'SDK main|62628d3'), 'sdk-main'),
           (re.compile(r'v1\.0\.17\b|24af48f'), 'sdk-117'),
           (re.compile(r'9127cb7|v1\.0\.19\b'), 'sdk')]
GOOD = ('ok', 'nosym')


def last_marker(text, markers, default):
    hits = [(m.start(), k) for pat, k in markers for m in pat.finditer(text)]
    return max(hits)[1] if hits else default


class Tree:
    def __init__(self, root):
        self.root, self.files, self.cache = root, [], {}
        for d, dirs, names in os.walk(root):
            dirs[:] = [x for x in dirs if x != '.git']
            self.files += [os.path.relpath(os.path.join(d, n), root) for n in names]

    def matches(self, path):
        return [path] if path in self.files else [f for f in self.files if f.endswith('/' + path)]

    def lines(self, rel):
        if rel not in self.cache:
            with open(os.path.join(self.root, rel), errors='replace') as f:
                self.cache[rel] = f.read().split('\n')
        return self.cache[rel]


def units(path):
    """Yield (first line no, text, heading line no) per paragraph, bullet or table row."""
    buf, start, heading, fenced = [], 0, 0, False
    with open(path) as f:
        lines = f.read().split('\n')
    for n, line in enumerate(lines + [''], 1):
        if line.lstrip().startswith('```'):
            fenced = not fenced
            continue
        if fenced or not line.strip() or line.startswith('#') or UNIT_START.match(line):
            if buf:
                yield start, '\n'.join(buf), heading
            buf = []
            if fenced or not line.strip() or line.startswith('#'):
                heading = n if line.startswith('#') else heading
                continue
        start = start if buf else n
        buf.append(line)


def group_around(mtext, pos, s=0):
    """(start, end) of the innermost parenthetical holding pos, else None."""
    depth, i = 0, pos
    while i > s:
        i -= 1
        depth += {')': 1, '(': -1}.get(mtext[i], 0)
        if depth < 0:
            j, d = pos, 1
            while j < len(mtext) and d:
                d += {'(': 1, ')': -1}.get(mtext[j], 0)
                j += 1
            return i, j
    return None


def segment(mtext, m):
    """The ;-separated part of the parenthetical holding span m, else None."""
    g = group_around(mtext, m.start())
    return g and (max([g[0]] + [i for i in range(g[0], m.start()) if mtext[i] == ';']),
                  min([g[1]] + [i for i in range(m.end(), g[1]) if mtext[i] == ';']))


def preceding(text, mtext, m):
    """Symbols written just before the parenthetical holding m: `a` / `b` (`x:1`)."""
    g = group_around(mtext, m.start())
    sm = g and re.search(r'(?:`[^`\n]+`\s*(?:/|,|or|and)?\s*)+$', text[:g[0]])
    return symbols(text, sm.start(), sm.end()) if sm else []


def group_after(text, mtext, end):
    """(group, direct): the parenthetical after a cite or a run of `, <cite>`
    spans, and whether it follows this cite directly."""
    start = end
    while True:
        m = re.match(r'\s*(?:,|and)\s*`([^`\n]+)`', text[end:])
        if not (m and (CITE.match(m.group(1)) or BARE.match(m.group(1)))):
            break
        end += m.end()
    if re.match(r'\s*\(', mtext[end:]):
        return group_around(mtext, end + mtext[end:].index('(') + 1, end), end == start
    return None, False


def symbols(text, a, b):
    """(offset, span, regexes) for each symbol span in text[a:b]."""
    out = []
    for m in SPAN.finditer(text, a, b):
        span = m.group(1).strip()
        if CITE.match(span) or BARE.match(span) or NOT_SYMBOL.search(span) or PATH.match(span):
            continue
        name = re.sub(r'^([\w.]+)\(.*\)$', r'\1', span)  # a call: match the callee
        if re.search(r'\w\*|\*\w', name) and ' ' not in name:  # a glob such as `GetAll*`
            pats = [re.escape(name).replace(r'\*', r'\w*')]
        else:
            pats = [r'(?<!\w)%s%s' % (re.escape(t), '' if t.endswith('_') else r'(?!\w)')
                    for t in TOKEN.findall(name) if len(t.strip('_')) >= 3]
        if pats:
            out.append((m.start(), span, pats))
    return out


def has_all(lines, a, b, pats, slack=SLACK):
    window = '\n'.join(lines[max(a - 1 - slack, 0):b + slack])
    return all(re.search(p, window) for p in pats)


def encloses(lines, a, pats):
    """A brace-style definition naming pats opens before line a, not yet closed."""
    for d in range(a - 1, 0, -1):
        if lines[d - 1].rstrip() == '}':
            return False
        if lines[d - 1][:1].strip() and '(' in lines[d - 1] and has_all(lines, d, d, pats, 0):
            return True
    return False


def evaluate(lines, ranges, cands):
    if any(a < 1 or b < a or b > len(lines) for a, b in ranges):
        return 'range', 'file has %d lines' % len(lines)
    if not cands:
        return 'nosym', ''
    if any(has_all(lines, a, b, p) or encloses(lines, a, p) for _, _, p in cands for a, b in ranges):
        return 'ok', ''
    for _, sym, pats in cands:
        hits = [i + 1 for i in range(len(lines)) if has_all(lines, i + 1, i + 1, pats, 0)]
        if hits:
            return 'moved', '`%s` at :%d' % (sym, min(hits, key=lambda n: abs(n - ranges[0][0])))
    return 'missing', 'symbol not in file: ' + ', '.join('`%s`' % c[1] for c in cands)


def resolve(trees, path, before, remembered):
    """Return ('ok', (tree key, relpath)) or (status, detail)."""
    version, marker = last_marker(before, VERSION, 'sdk'), last_marker(before, FAMILY, '')
    in_npa = bool(trees['npa'].matches(path))
    in_sdk = any(trees[k].matches(path) for k in (version, 'sdk', 'sdk-main') if k in trees)
    kernel = path.startswith(('kernel/', 'net/', 'fs/', 'include/linux/', 'include/uapi/'))
    if not in_npa and (not in_sdk or marker == 'ext' or kernel):
        ext = marker == 'ext' or version == 'sdk-117' or kernel
        return ('skipped', 'other repo, no tree') if ext else ('no-file', 'not in any tree')
    key = version if in_sdk and (not in_npa or marker == 'sdk') else 'npa'
    if key not in trees:
        return 'skipped', 'no %s tree' % key
    found = trees[key].matches(path)
    if len(found) > 1 and remembered.get((key, path)) in found:
        found = [remembered[(key, path)]]
    if len(found) != 1:
        return 'ambiguous', ' '.join(found)
    remembered[(key, path)] = remembered[(key, os.path.basename(found[0]))] = found[0]
    return 'ok', (key, found[0])


def check(trees, guide):
    results, history, cols, remembered = [], {}, {}, {}
    for start, text, heading in units(guide):
        mtext = SPAN.sub(lambda m: '`' + 'x' * (len(m.group(0)) - 2) + '`', text)
        hist, tcols = history.setdefault(heading, []), cols.setdefault(heading, {})
        bounds = [0] + [m.end() for m in SENTENCE_END.finditer(mtext)] + [len(text)]
        clauses = sorted(set(bounds + [m.end() for m in CLAUSE_END.finditer(mtext)]))
        spans, owned, unit_last = list(SPAN.finditer(text)), {}, None
        for m in spans:  # owned: symbol offset -> offsets of the cites it is tied to
            if CITE.match(m.group(1).strip()) or BARE.match(m.group(1).strip()):
                tied = [s for g in (group_after(text, mtext, m.end())[0], segment(mtext, m)) if g
                        for s in symbols(text, *g)] + preceding(text, mtext, m)
                for c in tied:
                    owned.setdefault(c[0], set()).add(m.start())
        for m in spans:
            span, before = m.group(1).strip(), text[:m.start() + 1]
            col = mtext.count('|', 0, m.start()) if text.startswith('|') else None
            cm, bm = CITE.match(span), BARE.match(span)
            if PATH.match(span):  # a file named without a line
                status, res = resolve(trees, span, before, remembered)
                unit_last = res if status == 'ok' else ('unresolved', span)
                hist.append(unit_last)
                if col is not None:
                    tcols.setdefault(col, unit_last)
                continue
            if not cm and not (bm and unit_last):
                continue
            gline = start + text.count('\n', 0, m.start())
            ranges = [tuple(int(x) for x in (p.strip() + '-' + p.strip()).split('-')[:2])
                      for p in (cm or bm).group('r').split(',')]
            if cm and cm.group('file'):
                status, res = resolve(trees, cm.group('file'), before, remembered)
                if status != 'ok':
                    results.append((gline, span, status, res))
                    unit_last = ('unresolved', cm.group('file'))
                    hist.append(unit_last)
                    continue
                targets = [res]
            elif bm:
                targets = [unit_last]
            else:
                targets = ([tcols[col]] if unit_last is None and col in tcols else []) + hist[::-1]
            if not targets or targets[0][0] == 'unresolved':
                what = targets[0][1] if targets else 'no earlier file'
                results.append((gline, span, 'skipped', 'refers to %s' % what))
                continue
            g, (ga, direct) = segment(mtext, m), group_after(text, mtext, m.end())
            cands = (g and symbols(text, *g)) or preceding(text, mtext, m)
            if not cands and ga:  # a parenthetical after a run belongs to its last cite
                cands = symbols(text, *ga) if direct else []
            elif not cands:
                s = max(b for b in clauses if b <= m.start())
                e = min(b for b in clauses if b > m.start())
                cands = [c for c in symbols(text, s, e) if owned.get(c[0], {m.start()}) & {m.start()}]
            cands.sort(key=lambda c: abs(c[0] - m.start()))
            tried = []
            for t in dict.fromkeys(x for x in targets if x[0] != 'unresolved'):
                tried.append((t,) + evaluate(trees[t[0]].lines(t[1]), ranges, cands))
                if tried[-1][1] in GOOD:
                    break
            (t, status, detail), alt = tried[0], tried[-1]
            if len(tried) > 1 and alt[1] == 'ok':
                t, status = alt[0], 'backref'
                detail = 'refers to %s, not last-named %s' % (t[1], tried[0][0][1])
            elif len(tried) > 1 and status == 'range':
                detail += '; in range in ' + (', '.join(x[0][1] for x in tried[1:] if x[1] != 'range') or 'none')
            unit_last = t
            if cm and cm.group('file'):
                hist.append(t)
            results.append((gline, '%s %s:%s' % (t[0], t[1], (cm or bm).group('r')), status, detail))
    return results


ORDER = ['ok', 'nosym', 'moved', 'backref', 'missing', 'range', 'no-file', 'ambiguous', 'skipped']
FAIL = {'missing', 'range', 'no-file', 'ambiguous'}


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--npa', required=True)
    ap.add_argument('--sdk', required=True)
    ap.add_argument('--sdk-main')
    ap.add_argument('guide')
    args = ap.parse_args(argv)
    trees = {'npa': Tree(args.npa), 'sdk': Tree(args.sdk)}
    if args.sdk_main:
        trees['sdk-main'] = Tree(args.sdk_main)
    results = check(trees, args.guide)
    counts = ', '.join('%s %d' % ('ok, no symbol' if k == 'nosym' else k,
                                  sum(1 for r in results if r[2] == k)) for k in ORDER)
    print('%d citations: %s' % (len(results), counts))
    for gline, label, status, detail in results:
        if status not in GOOD:
            print('%s:%d  %-9s %s  %s' % (os.path.basename(args.guide), gline, status, label, detail))
    return 1 if any(r[2] in FAIL for r in results) else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
