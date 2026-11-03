# Using AGENTS.md, the review guide and the diff helper

This repository has three files meant to be used while you write and review changes:

| File | What it is | Who reads it |
|---|---|---|
| `AGENTS.md` | Build and test commands, CI layout, and the hard rules that break enforcement, upgrades or rollbacks when missed | Coding agents load it automatically (see [Tools](#tools)). Humans: read it once. |
| `docs/review-guide.md` | The full checklist: SDK contracts, v4/v6 parity, precedents to reuse, recurring review themes. Each item is tagged `[blocking]` or `[advisory]` and cites code at a pinned commit. | Read the sections for the files your change touches. The routing table in section 1 maps files to sections. |
| `hack/v4v6-diff.py` | A normalized diff of each v4/v6 BPF source pair, so a change that lands in one family only stands out | Run it on any change under `pkg/ebpf/c/`. |

## While you write the change

1. **Find the sections that apply.** Look up the files you are changing in the routing table at the top of `docs/review-guide.md` and read those sections first. If you use a coding agent, ask it to do the same:

   ```text
   # A prompt for your coding agent before it starts editing
   Read AGENTS.md and the sections of docs/review-guide.md that cover the files
   this change will touch. List the [blocking] items that apply before you write code.
   ```

2. **Check v4/v6 parity** if you touched `pkg/ebpf/c/`. Run the helper at your merge base and at your change, and compare the hunk counts. A new hunk should be family-specific on purpose.

   ```bash
   # Extract the merge base's BPF sources into a scratch directory, without touching your checkout
   base=$(git merge-base origin/main HEAD)
   mkdir -p ../npa-base && git archive "$base" pkg/ebpf/c Makefile | tar -x -C ../npa-base

   # Diff every v4/v6 object pair at the merge base and at your change; --no-lines makes the two runs comparable
   python3 -I hack/v4v6-diff.py --all --no-lines ../npa-base > /tmp/parity-base.txt
   python3 -I hack/v4v6-diff.py --all --no-lines . > /tmp/parity-change.txt

   # Any output here is a hunk your change added, removed or altered; check whether it is family-specific
   diff /tmp/parity-base.txt /tmp/parity-change.txt
   ```

   The expected baseline at main is in section 4 of the guide.

3. **Go through the hard rules in `AGENTS.md`** before you push. They are the checks that most often cost a review round: pin prefixes without `_`, per-pod maps listed in `NamespacedBPFMaps`, `NPA_FILE_VERSION` when both directions must reload, no new flags, `ct_deny.h` and other headers needing a `.gitignore` exception.

## Before you open the PR

Go through the sections of `docs/review-guide.md` that the routing table names for your files, and check the items that apply to your change. A targeted lookup works better than handing the whole guide to an agent: in our evaluation (results in the description of [#730](https://github.com/aws/aws-network-policy-agent/pull/730)), an agent that read the guide during review caught no more of the maintainers' concerns than one that didn't. The guide did help it rate severity correctly.

If you ask an agent for a self-review, keep the guide out of its prompt and give it the severity bar instead:

```text
# A self-review prompt; run it on your branch before opening the PR
Review the diff between origin/main and HEAD. Report a finding as blocking only
if it causes wrong enforcement, a leak that grows without bound, state that
doesn't self-correct, or an upgrade or rollback that leaves nodes broken.
Everything else is advisory; keep advisory findings to one line each.
For any finding about pin names, SDK load behavior, NPA_FILE_VERSION or v4/v6
parity, check the matching entry in docs/review-guide.md before reporting it.
```

Then check the PR description:

- Which integration suites you ran, on IPv4 and IPv6, and on which kernels.
- For datapath or pinning changes: what happens on upgrade from the last release and on rollback to it.
- For changes that need an SDK change: the SDK version they need, and that the PR merges with or after that bump.
- Before and after numbers for anything performance- or memory-sensitive.

## When you review someone else's PR

The same applies: use the guide to check specific items the diff touches, not as a checklist to run in full. An item's tag is its worst case; rate each finding by its own reach and whether it self-corrects. An agent tends to report more concerns than a human reviewer would, so drop the ones you wouldn't raise yourself.

## Tools

Which tools load `AGENTS.md` without extra setup, per their documentation (checked November 2026):

| Tool | Loads `AGENTS.md` | Otherwise |
|---|---|---|
| Claude Code (v2.1.277 and later) | Yes, when the repository has no `CLAUDE.md` | If you add a `CLAUDE.md`, start it with `@AGENTS.md` ([docs](https://code.claude.com/docs/en/memory)) |
| Kiro | Yes ([docs](https://kiro.dev/docs/steering/)) | |
| GitHub Copilot coding agent and code review on github.com, VS Code agent mode | Yes ([docs](https://docs.github.com/en/copilot/reference/custom-instructions-support)) | |
| Copilot code review in VS Code | No, it reads `.github/copilot-instructions.md` only | Paste the review prompt above, or point it at the files |
| Amazon Q Developer CLI | Not by default | Add `file://AGENTS.md` to your agent's `resources` |

## Keeping the guide current

- **Citations** are `path:line` at a named commit. When main moves far enough that lines drift, re-pin: check every citation at the new commit and update the commit named in section 1. Find a moved line by the quoted symbol.
- **Checking citations.** `hack/check-guide-cites.py` checks every citation against checkouts of the pinned commits and reports each one as ok, moved, missing or out of range. With the NPA, SDK v1.0.19 and SDK main trees checked out next to this repository, run from the repository root:

  ```bash
  # Check every path:line citation in the guide against the pinned trees; exits 1 on missing or out-of-range cites
  python3 -I hack/check-guide-cites.py --npa ../npa-main-4bf96cf --sdk ../sdk-v1.0.19 --sdk-main ../sdk-main-62628d3 docs/review-guide.md
  ```

  A `moved` or `missing` result can be a false positive when the quoted symbol is a map or kfunc name rather than code on that line; read the line before changing the cite.
- **New entries.** New SDK-contract entries follow the section 3 shape (**Rule.**, **Why.**, **Cites.**); new precedents follow section 5. Each has a severity tag and a one-line bullet in the section 2 checklist. Add an entry when a review finds a repository-specific problem a strong general reviewer would likely miss. General review hygiene goes in the single list in section 2, not in new entries.
- **Measuring it.** The guide was evaluated by having an agent review held-out PRs (PRs it was not built from) with and without it, and comparing what each raised with what the maintainers raised. Re-run that check after large changes, preferably on recent PRs that touch the areas the guide covers.
