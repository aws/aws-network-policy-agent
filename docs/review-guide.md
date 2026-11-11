# Review guide for aws-network-policy-agent

## 1. Purpose and how to use it

This guide lists the problems maintainers keep finding in review, so authors and reviewers can find them first. It covers four areas: the implicit contracts of `aws-ebpf-sdk-go`, v4/v6 parity, existing precedents to reuse, and recurring review themes.

An item is tagged `[blocking]` when, whenever its condition holds, the change causes wrong enforcement (traffic allowed that policy denies, or denied that it allows), a leak that grows without bound, a state that doesn't self-correct (stuck until a restart or manual action), or an upgrade or rollback that leaves nodes broken after it completes. It is `[advisory]` if the harm is transient (it self-corrects on the next reconcile, retry or reattach), needs an unusual precondition, or is about quality, noise, tests or docs. Each blocking item has a "Blocking when:" clause, and some advisory items a "Blocking only if:" clause, that names the condition that makes an instance blocking. Report blocking findings first and keep advisory ones brief. The tag is the item's worst case, so judge each finding's own severity by its reach and whether it self-corrects, and don't copy the tag.

Run it against a diff. For each changed area, look up the matching checks:

| If the diff touches | Read |
|---|---|
| `pkg/ebpf/bpf_client.go`, `pkg/ebpf/conntrack/`, `pkg/ebpf/events/`, `pkg/clihelper/`, any `goelf.*` / `tc.*` / `goebpfmaps.*` call | [Quick checklist: SDK boundary](#ck-sdk), [section 3](#sdk), [P15](#p-scale) |
| `pkg/ebpf/c/*` | [BPF programs](#ck-bpf), [v4/v6 parity](#parity), [P2](#p-change) |
| A file with a `v4`/`v6` or `IPv6` twin, or a header with `_v4`/`_v6` functions | [v4/v6 parity](#parity) |
| `checkAndUpdateBPFBinaries`, `recoverBPFState`, `ReAttachEbpfProbes`, `NewBpfClient`, `legacy_pin_migration.go`, pinned maps | [Upgrade, downgrade, recovery](#ck-upgrade), [precedents](#precedents) |
| `pkg/utils/cp/`, `Makefile`, `Dockerfile`, `.gitignore` | [Host files and binaries](#ck-host) |
| Metrics, log lines, flags | [Metrics, logging and flags](#ck-obs), [P6](#p-metrics), [P8](#p-flags) |
| `controllers/`, `GetPodIdentifier` | [Controllers and pod identifiers](#ck-ctrl), [P12](#p-podid), [P13](#p-cache), [P14](#p-requeue) |
| `test/`, `scripts/`, `.github/workflows/` | [Tests and CI](#ck-tests), [P11](#p-tests), [P12](#p-podid) |
| Any change | [General review hygiene](#ck-general) |

To compare a change with its merge base without writing to the repository, extract both trees: `git archive <rev> pkg/ebpf/c | tar -x -C <dir>`. See [Running the diff helper](#parity-diff).

**Citations.** Every citation is `path:line` at a named commit. If a line has moved, find it by the quoted symbol.

- NPA: `aws/aws-network-policy-agent` at `4bf96cf`.
- SDK: `aws/aws-ebpf-sdk-go` v1.0.19 at `9127cb7`, the version NPA pins. Citations marked v1.0.17 are at `24af48f`, the version NPA v1.4.2 and v1.4.3 pin (earlier releases pin v1.0.15 or older). Citations marked SDK main are at `62628d3`. SDK v1.0.20 (`f871684`, released 2026-11-03) contains `62628d3`; NPA does not pin v1.0.20 yet.
- Libraries, as pinned in NPA `go.mod`: `vishvananda/netlink` v1.3.1, `go.uber.org/zap` v1.28.0.
- VPC CNI chart: `aws/amazon-vpc-cni-k8s` at `a149c83c`.
- EKS AMI: `awslabs/amazon-eks-ami` at `6832b07b`.

**SDK version.** NPA at `4bf96cf` pins SDK v1.0.19 (`go.mod:8`), since [#704](https://github.com/aws/aws-network-policy-agent/pull/704). NPA v1.4.2 and v1.4.3 pin v1.0.17 (older releases pin older versions), and no NPA release pins v1.0.18. Between v1.0.17 and v1.0.19 the SDK changed in two ways that matter here:

- kfunc support (`pkg/btf`, `pkg/internal/btf`, kfunc relocation in `elfparser`) is new in v1.0.18. v1.0.17 has none.
- `CleanupQdiscs` and `GetAllAttachedProgIds` switched from host-hook directions to pod directions in v1.0.19, with no signature change. This now matters when rolling back to an NPA release, all of which run v1.0.18 or earlier. See [C11](#c11).

All other SDK behavior cited here is the same in v1.0.17 and v1.0.19. Among existing files only `pkg/elfparser/elf.go`, `pkg/progs/loader.go` and `pkg/tc/tc.go` change between the two tags (`git diff v1.0.17 v1.0.19`, `24af48f..9127cb7`), and outside `CleanupQdiscs` and `GetAllAttachedProgIds` every change takes effect only for an object that calls a kfunc. Line numbers differ between versions.

SDK main at `62628d3` has two changes that v1.0.19 lacks: [SDK #179](https://github.com/aws/aws-ebpf-sdk-go/pull/179) releases what a failed load created ([C8](#c8)), and [SDK #176](https://github.com/aws/aws-ebpf-sdk-go/pull/176) retries map updates that return ENOMEM (`pkg/maps/loader.go:324-340`). Both are in SDK v1.0.20 (released 2026-11-03). NPA main still pins v1.0.19, so they reach NPA only after a `go.mod` bump to v1.0.20.

Items marked "(unverified)" or "(inferred)" rest on reasoning, or on kernel or Kubernetes behavior that was not traced in source. Treat them as questions, not facts. Kernel cites are `path:line` at Linux v6.1, with v5.10 or v6.12 noted where they differ. Cluster checks name the cluster, the node kernels and the date.

## 2. Quick checklist

<a id="ck-sdk"></a>
**SDK boundary**

- [blocking] Can any `LoadBpfFile*` prefix contain `_`, including through `GetPodIdentifier`? [C1](#c1) Blocking when: a new or changed prefix contains `_` for ordinary names, such as a constant or a generated name pattern. The `_` from a dotted pod name is already on main.
- [blocking] Is every new per-pod map in `NamespacedBPFMaps`? [C2](#c2) Blocking when: a per-pod map is missing from the list and userspace reads or writes it through `BpfData.Maps` after a restart.
- [advisory] Is any global map name defined by two ELFs? What reloads the programs that use a reloaded global map? [C3](#c3) Blocking only if: a second ELF defines a global map name another ELF already defines, so later loads bind to a different map than running programs, or a reload path leaves attached tc programs on the old map with no reattach to follow.
- [advisory] Does new startup or CLI code recover globals first, and does it handle partial recovery? [C4](#c4) Blocking only if: new code pins under `/sys/fs/bpf/globals/aws/` without the `<prefix>_<name>` shape, so recovery aborts or the agent panics on every start.
- [advisory] Is each field read from `BpfData` populated by the API that produced it? [C5](#c5) Blocking only if: the misread field decides an attach, detach or map write, for example a `ProgID` from `RecoverAll*`, which is always 0.
- [advisory] For each `UnPinMap`, `UnPinProg` or close: which other copies hold that FD? [C6](#c6) Blocking only if: the change closes or unpins a global map FD (for example `range bpfData.Maps { UnPinMap }` on `RecoverAll*` data) while the process still loads ELFs.
- [advisory] Which lock keeps this load away from other loads with the same prefix? [C7](#c7) Blocking only if: a new SDK caller loads a pod's prefix without `podIdentifierLocks` on the CNI ADD or reconcile path, which run concurrently.
- [advisory] What happens if this load fails half way under a live prefix? [C8](#c8) Blocking only if: the change reloads under an attached pod's prefix as a routine step, or retries a load that fails the same way each time (FDs leak per try).
- [advisory] Is `GetAllAttachedProgIds`'s error checked before `CleanupQdiscs`? Does anything else put tc filters on `eni*`/`vlan*`? [C9](#c9) Blocking only if: the change adds another tc filter with handle `0x1` on `eni*`/`vlan*`, or widens the prefix list to interfaces the agent doesn't own. A missing error check alone needs a netlink failure.
- [advisory] Is the detach-then-attach gap acceptable? Is a new error-string match on TC errors avoidable? [C10](#c10) Blocking only if: the change enables `nl.EnableErrorMessageReporting`, so the `file exists` match stops matching and every stale-filter retry fails (tested: the error becomes "file exists: Filter already exists"), or adds an attach path that leaves the hook empty with no later attach to refill it.
- [blocking] Which SDK version does `go.mod` pin, and does the caller assume pod or host direction? [C11](#c11) Blocking when: the caller assumes the other SDK version's direction convention, or the change alters only one direction's objects and n-1 runs SDK v1.0.18 or earlier.
- [advisory] Is `errors.Is(err, unix.ENOENT)` used only after a next-key API? Is `CreateMapEntry` meant to keep an existing value? [C13](#c13) Blocking only if: the change relies on `CreateMapEntry` to replace a policy, pod-state or conntrack value, which keeps the old value.
- [advisory] Is `CheckKfuncs` called once at startup, and what happens if a kfunc load fails later? Where does the failure reason show? [C17](#c17), [C19](#c19) Blocking only if: the object is chosen after startup or per pod with no fallback, so a kfunc load failure leaves pods unattached on every retry.
- [advisory] Is there exactly one `InitRingBuffer` call, and does its consumer avoid blocking work? [C18](#c18)
- [advisory] Does the change hard-code `/sys/fs/bpf` paths or path depth? [C20](#c20)
- [blocking] Does a failure path unpin or close a program that an attached filter still runs? Does a rollback run under the identifier lock and unload only what this call loaded? [C21](#c21) Blocking when: a failure path unpins or closes a program that an attached filter still runs without detaching that filter, or unloads a program that was already in the context.
- [advisory] Does a periodic task read a node-wide kernel table in full? What does its memory scale with, and what is the agent's RSS at a large table? [P15](#p-scale)

<a id="ck-bpf"></a>
**BPF programs (C)**

- [blocking] Do Go key and value sizes equal the C `key_size` / `value_size`? [C12](#c12) Blocking when: a Go key or value type differs from the C `key_size` / `value_size`, or its padding differs from the C struct.
- [blocking] Is `struct bpf_map_def_pvt` unchanged (7 x `__u32`, pinning 6th), and is every `.pinning` `PIN_GLOBAL_NS`? [C14](#c14) Blocking when: the change edits `struct bpf_map_def_pvt` or adds a map whose `.pinning` is not `PIN_GLOBAL_NS`.
- [blocking] Does any code read a kernel-internal struct field, a global variable, or a `.maps` map? [C15](#c15) Blocking when: BPF code dereferences a kernel-internal struct field, or adds a global variable, `bpf_printk`, `SEC(".maps")` or `BPF_CORE_READ`.
- [blocking] Is every program section in the SDK's set, and do function names match `TC_*_PROG`? [C16](#c16) Blocking when: a program uses a section outside the SDK's set, or a program function is renamed without its `TC_*_PROG` constant.
- [blocking] Are helpers that call kfuncs `__always_inline`? [C16](#c16) Blocking when: a helper that calls a kfunc is not `__always_inline`, so the kfunc call sits in a `.text` subprogram and the object fails to load.
- [blocking] Is the change made in all four tc programs, and in both events files if it touches a shared struct? [Parity](#parity) Blocking when: an enforcement change or a shared-struct change is missing from one of the four tc programs or one events file.
- [advisory] Does the change alter the bytes of objects whose behavior it doesn't change, for example through an `#include` or a comment? [P2](#p-change) Blocking only if: the byte change touches only one direction's objects and n-1 runs SDK v1.0.18 or earlier ([C11](#c11)).
- [blocking] Is an existing conntrack value encoding reused with a new meaning, in this version or relative to n-1? The pinned map survives upgrade and rollback. [Theme 14](#themes) Blocking when: the events object is unchanged, so the conntrack map survives, and n-1 and this version read the same stored value differently.
- [blocking] Does a deny or a bypass depend on a map lookup hitting (an LRU, a set keyed by tuple, an entry another program writes later)? Then is the path taken on a miss safe by itself, and was it tested with the rest of policy allowing the packet? Two packets on one tuple, an eviction, or a reordering through a redirect each cause a miss. [Theme 21](#themes) Blocking when: a miss sends the packet down a path that records a flow or allows traffic that policy denies.

<a id="ck-parity"></a>
**v4/v6 parity**

- [blocking] Is the same change in the v4 and v6 C programs, conntrack GC, event decoding, CLI and tests? [Parity table](#parity-table) Blocking when: a change to what a C program or conntrack GC allows, denies or deletes lands in one family only. A missing CLI, event-decode or test twin is advisory.
- [advisory] Does `hack/v4v6-diff.py` show new hunks on the change compared with its merge base? [Diff helper](#parity-diff) Blocking only if: the new hunk changes what one family allows or denies.
- [advisory] Does a shared header define `_v4`/`_v6` function pairs? Run the helper's `--funcs` mode on it. [Diff helper](#parity-diff) Blocking only if: a pair differs in more than address types and copies, and that changes one family's verdict.

<a id="ck-upgrade"></a>
**Upgrade, downgrade, recovery**

- [advisory] Does a changed object get reloaded by the byte compare? If the logic is unchanged but a reload is needed, is `NPA_FILE_VERSION` bumped in all four tc programs? [P2](#p-change) Blocking only if: pods must run a new program but every shipped object's bytes equal n-1's, so no node reloads it.
- [blocking] Does the change alter only one direction's objects relative to n-1? If n-1 runs SDK v1.0.18 or earlier (every NPA release up to v1.4.3), its cleanup on rollback removes the other direction's filters. [C11](#c11), [P2](#p-change) Blocking when: the change alters only one direction's objects and n-1 runs SDK v1.0.18 or earlier.
- [advisory] Does any startup load happen before the events-binary decision, and does it depend on the conntrack value layout? [C4](#c4), [P5](#p-recovery) Blocking only if: a program loaded before the events load stays attached after the events load replaces `aws_conntrack_map` ([C3](#c3)). A probe that only picks the variant is advisory.
- [advisory] Does the events object change? If so, every pod is reattached with default state and the conntrack map is recreated. Is that intended? [P2](#p-change)
- [advisory] Does a one-time host migration follow the marker-file pattern? [P3](#p-marker) Blocking only if: a failed step can still write the marker, so the migration is never retried.
- [advisory] Is new pinned state recovered through `recoverBPFState`, not a parallel path? [P4](#p-map), [P5](#p-recovery) Blocking only if: no path recovers the new state, so every restart loses it until the pod is re-created.

<a id="ck-host"></a>
**Host files and binaries**

- [blocking] Is a new object in `bpfBinaries`, `Makefile` `build-bpf`, `Dockerfile` `COPY`, and the name checks in `checkAndUpdateBPFBinaries`? [P2](#p-change) Blocking when: the object is missing from any of the four. The image then lacks it, or nodes never install or reload it, and its load fails.
- [advisory] Does a family or feature variant install under one stable host name? [P1](#p-hostname) Blocking only if: a rollback or variant switch then skips a reload it needs because the compare reads a stale host copy (inferred).
- [advisory] Does a new header in `pkg/ebpf/c/` have a `.gitignore` exception? `.gitignore` ignores `*.h`. [P2](#p-change)
- [advisory] Do host-side tests call `/opt/cni/bin/aws-eks-na-cli` on both families? [P1](#p-hostname)

<a id="ck-obs"></a>
**Metrics, logging and flags**

- [advisory] Does the change reuse `sdkAPILatency` / `sdkAPIErr` with a new, greppable label value? [P6](#p-metrics)
- [advisory] Does anything that parses flow logs handle both the v4 and v6 formats? [P7](#p-logging)
- [advisory] Does the change add an agent flag? Could it ship without one? If a test needs another code path, can a test-only mechanism provide it? [P8](#p-flags)
- [advisory] Is a new flag also added to the VPC CNI chart? [P8](#p-flags)

<a id="ck-tests"></a>
**Tests and CI**

- [advisory] Is the test in a suite that CI actually runs, including the nightly kernel workflow for eBPF changes? [P11](#p-tests)
- [advisory] Does a suite that changes aws-node run late, after the suites that expect the stock agent and before `strict`, and restore what it changed even if the script stops mid-suite? [P11](#p-tests)
- [advisory] Is there a privileged test that loads the built ELF, for C changes that only fail at load time? [C16](#c16)
- [advisory] Is a feature gate tested on both sides of the gate, given that CI nodes are AL2023 only? [P9](#p-gate)
- [advisory] Do test pods that need separate programs have names that differ before the last `-`, and no `.`? [P12](#p-podid)
- [advisory] Does a test that reads the node's conntrack table look the tuple up with `conntrack -G`, not by scanning `/proc/net/nf_conntrack`? [P11](#p-tests)
- [advisory] Does a claim about which suites run on which family come from the suite's code, not a CI comment or label? [P11](#p-tests)
- [advisory] Does a new spec pass only with an SDK change that `go.mod` doesn't pin yet? Then it merges with or after the bump, and the PR says so. [P11](#p-tests)

<a id="ck-ctrl"></a>
**Controllers and pod identifiers**

- [blocking] Does new code write to an object read with `client.UnsafeDisableDeepCopy`, including slice elements and pointers inside it? [P13](#p-cache) Blocking when: code writes through any value reached from a cached object, including slice elements and the `Protocol` / `Port` / `EndPort` pointers.
- [advisory] Can two pods that should be enforced separately end up with one pod identifier? [P12](#p-podid) Blocking only if: pods that commonly share an identifier, such as replicas of one Deployment, need different values of the new state. A collision that needs an unusual pod name is advisory.
- [blocking] Does every failure that leaves datapath state wrong reach `Reconcile`'s return value, after the loop finishes the other identifiers? [P14](#p-requeue) Blocking when: a failure that leaves rules, pod state or an attach wrong is logged and dropped. An expected, benign error that now requeues is advisory.

<a id="ck-general"></a>
**General review hygiene**

These apply to any change. Where a line links an entry, that entry makes it specific to NPA.

- [advisory] What happens to pinned programs, pinned maps, tc filters and conntrack entries on upgrade, on rollback to n-1, and on a crash between any two startup steps? [P2](#p-change), [P5](#p-recovery) Blocking only if: a node is still broken after the upgrade or rollback completes, or the next start does not rebuild the state.
- [advisory] Does the PR name the n-1 versions it is safe to roll back to? Rollback runs n-1's SDK. [C11](#c11), [P2](#p-change) Blocking only if: the change alters only one direction's objects and n-1 runs SDK v1.0.18 or earlier ([C11](#c11)).
- [advisory] After a crash between any two steps, is state rebuilt exactly, with markers written last? [P3](#p-marker), [P5](#p-recovery), [C4](#c4) Blocking only if: the next start cannot rebuild the state at all, so it stays wrong until someone fixes the node by hand.
- [advisory] Is each failure returned so it retries, and will each retried error resolve? Match errors by type or sentinel, not text. [P14](#p-requeue), [C10](#c10), [C13](#c13) Blocking only if: a failure that leaves datapath state wrong returns nil ([P14](#p-requeue)).
- [advisory] Is each `unsafe.Pointer` to `uintptr` conversion inside the syscall expression, with `KeepAlive` on the real object? The SDK map APIs take raw `uintptr`s with no size check. [C12](#c12) Blocking only if: a buffer is shorter than the map's key or value size ([C12](#c12)).
- [advisory] Was the change run on an IPv6 cluster? The `pkg/ebpf` unit tests mostly exercise v4 only. [v4/v6 parity](#parity), [P11](#p-tests)
- [advisory] Each new test fails on main, passes with the change, calls production code, and avoids sleeps and absolute counts.
- [advisory] Tests cover IPv4 and IPv6, and strict and standard mode. [P10](#p-mode)
- [advisory] New logic is written once. A family switch reuses the existing selection code. [Parity table](#parity-table)
- [advisory] A new failure mode shows in a log line or metric, or the PR says it is only in the SDK log. [C19](#c19)
- [advisory] A timer covers only the operation it names, with sub-millisecond precision. [P6](#p-metrics)
- [advisory] A log line doesn't fire per entry, per pod or per retry at the default `debug` level, and an error is logged at one layer. [P7](#p-logging)
- [advisory] The PR says how an operator turns a gated behavior off, even if the answer is "roll back the agent". [P8](#p-flags), [P9](#p-gate)
- [advisory] Comments describe current behavior and why, without change history.
- [advisory] The PR description matches the final code and lists test results (families, OS, kernels, upgrade and downgrade).
- [advisory] Hot-path or scale changes attach before/after numbers. [P15](#p-scale)
- [advisory] The change is in the right layer (SDK or controller). If it needs an SDK change, the SDK release comes first. [P11](#p-tests)
- [advisory] Concurrency is real (reconciler workers, CNI RPC path) before a sync primitive is added.

<a id="sdk"></a>
## 3. SDK contracts

These are rules a caller must follow that the SDK neither enforces nor documents. "Silent" means no error reaches the caller and nothing is logged at error level in the agent log.

<a id="c1"></a>
### [blocking] C1. Pin prefixes must not contain `_`

Blocking when: a new or changed prefix contains `_` for ordinary names, such as a constant or a generated name pattern. The `_` that a dotted pod name produces through `GetPodIdentifier` is already on main.

**Rule.** Every `CustomPinPath` / prefix passed to `LoadBpfFile*` must be non-empty and free of `_`. The part of a pin name after its first `_` must equal the ELF map or function name.

**Why.** The SDK splits pin names at the first `_` to find the namespace. With prefix `A_B`, the map pin `A_B_ingress_map` parses as namespace `A`, name `B_ingress_map`. That name is not namespaced, so the map is treated as global. At load time it is cached under its bare ELF name, so the SDK cache now maps `ingress_map` to this pod's FD (`elf.go:273-276`). At the next restart, `RecoverAllBpfProgramsAndMaps` cannot find the program's namespace and aborts the walk with "failed to get err", unless another pod's prefix is exactly `A` (then the walk continues, but this program's map is recovered under the name `B_ingress_map`). When it aborts, no pod on the node is recovered. The load itself is silent.

**Cites.** SDK 9127cb7: `pkg/elfparser/elf.go:1145` (`strings.Cut(lastSegment, "_")`), `elf.go:242-246` and `1047-1051` (pin = prefix + `_` + name), `elf.go:1311` (prog split), `elf.go:1343-1347` (abort). NPA 4bf96cf: `pkg/utils/utils.go:173-188` (`GetPodIdentifier` joins with `@` for this reason); the ct-deny probe prefix `CTDENYPROBE` has no `_` for the same reason (`pkg/ebpf/bpf_client.go:1080-1086`).

SDK main (`62628d3`, #179) classifies a loaded map as global by its ELF map name, not its pin path (`elf.go:349-351`), so the load-time cache entry above no longer depends on the prefix. The recovery walks, and so the abort, are unchanged by #179.

The code doesn't enforce this today: `GetPodIdentifier` replaces `.` in the pod name with `_` (`utils.go:178-181`). See [P12](#p-podid) for the rest of the identifier rules.

**Check.** `grep -n 'LoadBpfFile' -r pkg`. Every prefix must be a constant without `_`. A `GetPodIdentifier` result is not safe today (dotted pod names produce `_`). A unit test can assert `GetMapNameFromBPFPinPath(MAP_BPF_FS + prefix + "_ingress_map")` returns `("ingress_map", prefix)` for each prefix shape. The method is not on `BpfSDKClient`, so call it via `goelf.New(cfg).(interface{ GetMapNameFromBPFPinPath(string) (string, string) })`.

<a id="c2"></a>
### [blocking] C2. Every per-pod map must be in `NamespacedBPFMaps`

Blocking when: a per-pod map in a tc ELF is missing from `NamespacedBPFMaps` and userspace reads or writes it through `BpfData.Maps` after a restart.

**Rule.** Every `SEC("maps")` symbol in a per-pod ELF must be listed in `Config.NamespacedMaps`.

**Why.** An unlisted map is global to the SDK. `RecoverGlobalMaps` caches every global pin under its bare name, last writer wins. `RecoverAllBpfProgramsAndMaps` checks that cache before the pod's own FD. After a restart, every pod except the last one walked has `Maps["newmap"]` holding another pod's FD with its own map ID. Writes go to the wrong pod's map. Silent, and only after a restart (fresh loads use local maps first).

**Cites.** SDK 9127cb7: `elf.go:1157-1160` (`IsMapGlobal`), `elf.go:1188`, `1204` (cache set), `elf.go:1352-1364` (cache before local). NPA 4bf96cf: `pkg/utils/utils.go:52-62`, passed at `pkg/ebpf/bpf_client.go:195` and `pkg/clihelper/show.go:41`.

**Check.** `grep -n 'SEC("maps")' pkg/ebpf/c/tc.*.bpf.c` and compare with `NamespacedBPFMaps`. See [P4](#p-map) for the other places a new map must be added.

<a id="c3"></a>
### [advisory] C3. Global map names are one process-wide namespace

Blocking only if: a second ELF defines a global map name that another ELF defines, or a reload path leaves attached tc programs on the old map with no reattach to follow.

**Rule.** A global map name must be defined by exactly one ELF in the process. When that ELF is reloaded, every program that uses its maps must be reloaded too.

**Why.** The SDK has one package-level FD cache keyed by bare map name, shared by every `elfparser.New` client, never cleared. Relocation writes the FD into the instruction at load time. A second ELF that defines `aws_conntrack_map` overwrites the cache, so later loads bind to the new map while loaded programs keep the old one. Reloading the events ELF unlinks and re-pins the conntrack map, so old TC programs write a map that userspace no longer reads. Silent in both cases.

**Cites.** SDK 9127cb7: `pkg/cache/cache.go:23,58-71`, `elf.go:56`, `elf.go:731-740`, `pkg/maps/loader.go:231-261`. NPA 4bf96cf: events ELF loaded with prefix `global` (`pkg/ebpf/bpf_client.go:266-275`). A byte-compare change in the events binary forces both TC directions to reload (`bpf_client.go:214`, `229-231`). The missing-global-map path (`:260`, also reached after a `RecoverGlobalMaps` error at `:504-508`) reloads the events ELF without reloading TC programs, so it does not meet this contract until each pod is re-attached.

**Check.** `grep -n 'SEC("maps")' pkg/ebpf/c/*.c`. Ask: "If this ELF is reloaded, what reloads everything that references its maps?"

<a id="c4"></a>
### [advisory] C4. Recovery: order, all-or-nothing, and foreign pins

Blocking only if: new code leaves a pin under `/sys/fs/bpf/globals/aws/` that the recovery walk cannot parse, so recovery aborts or the agent panics on every start.

**Rule.**

- In each process, run `RecoverGlobalMaps` (or load the ELF that defines the globals) before `RecoverAllBpfProgramsAndMaps` and before loading any ELF that uses globals it doesn't define.
- Only SDK-created pins may exist under `/sys/fs/bpf/globals/aws/maps/` and `/programs/`. Every program pin name must contain `_`.
- A `RecoverGlobalMaps` error can mean "no maps directory yet". Don't call it in a loop.
- A load at startup that uses globals the ELF doesn't define relocates against whatever is pinned. Before the events-binary decision, that is the previous agent's maps.

**Why.** Global FDs reach relocation and recovery only through the cache. Any per-entry error aborts the `filepath.Walk` and the function returns no results, so one bad pin loses recovery for the whole node. A program pin name without `_` panics with an index out of range. The agent exits and (inferred) restarts into the same panic on every start. `RecoverGlobalMaps` fails when the maps directory is missing (for example after a reboot, unverified) and opens one new FD per global pin on each call without closing the old ones.

**Cites.** SDK 9127cb7: `elf.go:731-736`, `elf.go:1171-1222`, `1259-1296`, `1300-1392` (walks), `elf.go:1311-1312`, `1470-1471` (`podIdentifier[1]`), `elf.go:1197-1204`, `1277-1279`, `1352-1361` (globals only from the cache). NPA 4bf96cf: `pkg/ebpf/bpf_client.go:499-533` (order; errors logged, never fatal). A `RecoverGlobalMaps` error returns early (`:504-508`), so per-pod recovery is skipped too. The ct-deny probe recovers the globals first (`chooseIngressBinary`, `:1115`) and `recoverBPFState` reuses them (`:500-503`), so a start that recovers globals opens their FDs once.

The events-binary decision is the compare at `bpf_client.go:214`, and the events load follows at `bpf_client.go:260-275`. A startup load placed before the events load binds to the `aws_conntrack_map` the previous agent pinned. Its layout depends on that agent's version: `struct conntrack_value` is `{ __u8 val; }` (1 byte) up to v1.4.2 and `{ __u64 val; __u64 last_seen; }` (16 bytes) from v1.4.3 (`pkg/ebpf/c/v4events.bpf.c:41` at both tags). A validation or probe load whose program reads the 16-byte value then fails, or passes, depending on the version being upgraded from. Probing before the events load after v1.4.2 failed with "invalid access to map value, value_size=1 off=0 size=8", and the same early probe after v1.4.3 passed (checked on np-npa-repro, AL2023 6.1.188, 2026-10-27). The ct-deny probe is such a load and handles this: it probes before the events load only when the events binary is unchanged and the globals recover, and otherwise after the events load (`chooseIngressBinary`, `bpf_client.go:1103-1125`; deferred probe at `bpf_client.go:318`).

**Check.** In any new startup or CLI path, trace the first SDK call. For a load before `bpf_client.go:260`, ask what it binds to when the events binary changes, and whether it can wait until after the events load. Any code that pins under `/sys/fs/bpf/globals/aws/` outside `LoadBpfFile*` (test helpers, migrations) must keep the `<prefix>_<name>` shape. Count `RecoverGlobalMaps` calls per process.

<a id="c5"></a>
### [advisory] C5. `BpfData` contents depend on the API that produced it

Blocking only if: the misread field decides an attach, detach or map write, for example a `ProgID` from `RecoverAll*`, which is always 0.

**Rule.** Don't assume `Maps`, `MapFD`, `ProgFD` or `ProgID` mean the same thing across APIs.

| API | `Maps` | Program fields |
|---|---|---|
| `LoadBpfFile*` | Only maps this ELF defines **and** the program references. Globals from the cache are absent | `ProgFD`, `ProgID` set |
| `RecoverAllBpfProgramsAndMaps` | All associated maps, including globals (cache FD) | `ProgFD`, `PinPath`; `ProgID == 0` |
| `GetAllBpfProgramsAndMaps` | Every `MapFD` is 0 | `ProgID` set; no `ProgFD` |

**Why.** `MapFD` from `GetAll*` is FD 0 (stdin): wrong but loud. Every map syscall resolves the FD through `__bpf_map_get`, which returns `EBADF` for a closed FD and `EINVAL` for an open FD that is not a BPF map (Linux v6.1 `kernel/bpf/syscall.c:1198-1205`, used at `:1326` and `:1398`; same in v5.10 and v6.12). It would be silent only if FD 0 were itself a BPF map, which needs the process to have closed stdin first (inferred). `ProgID` from `RecoverAll*` is 0: silent if compared.

**Cites.** SDK 9127cb7: `elf.go:726-730`, `1113-1131`, `1307-1325`, `1484`, `1512`. NPA 4bf96cf: uses only `ProgID` from `GetAll*` (`pkg/ebpf/bpf_client.go:628-632`), looks maps up by name (`bpf_client.go:546`), rejects a load with empty `Maps` (`bpf_client.go:1201-1204`).

**Check.** For each new `BpfData` field read, name the API that produced it.

<a id="c6"></a>
### [advisory] C6. FD ownership and stale copies

Blocking only if: the change closes or unpins a global map FD (for example `range bpfData.Maps { UnPinMap }` on `RecoverAll*` data) while the process still loads ELFs. Later loads then relocate against a dead FD until restart.

**Rule.** Close the FDs you are given, except global map FDs, which the SDK cache also holds. Never close or unpin a global map's FD while the process may still load ELFs that reference it. After `UnPinMap` / `UnPinProg`, drop every other copy of that `BpfMap` / `BpfProgram`. Treat FD 0 as "no FD".

**Why.** `UnPinMap` zeros `MapFD` only on its receiver. `BpfMap` is a value type, copied into `BpfData.Maps` and the second return of `LoadBpfFile*`; the SDK cache keeps the FD number. A later use of a stale copy hits an FD number the kernel may have reassigned. If it now names a compatible map, the write or relocation goes to the wrong map (unverified: kernel accepts it silently). `BpfData.Maps` from `RecoverAll*` includes the globals, so `for ... range Maps { UnPinMap }` closes the SDK cache's FD for `aws_conntrack_map` and `policy_events` (and unpins them if the caller derives pin paths from map names). Later loads in this process then relocate against a dead FD.

| API | FD returned | Who closes |
|---|---|---|
| `LoadBpfFile*` | prog FD and map FDs | caller, except global maps |
| `GetProgFromPinPath`, `utils.GetMapFDFromID` / `GetProgFDFromID` | open FD | caller |
| `GetMapFromPinPath` | none | SDK |
| `RecoverGlobalMaps` | one FD per global pin | shared with the cache |
| `RecoverAllBpfProgramsAndMaps` | prog FDs, per-pod map FDs; globals use cache FDs | caller, not globals |
| kfunc module BTF | held by the resolver | never |

**Cites.** SDK 9127cb7: `pkg/maps/loader.go:268-286`, `pkg/progs/loader.go:243-260`, `elf.go:249-276`, `344-363`, `1350-1378`, `pkg/utils/utils.go:140-178`. NPA 4bf96cf: unpins only named per-pod maps (`pkg/ebpf/bpf_client.go:1040-1066`); uses `ProgFD != 0` as "loaded" (`bpf_client.go:893`). `ingressProgToPodsMap` is keyed by prog FD number (`bpf_client.go:866-874`), so it is exposed to FD reuse. The ct-deny probe closes only the FDs `LoadBpfFile` returned, which exclude the global maps (`bpf_client.go:1133-1147`).

**Check.** `grep -n 'UnPinMap\|UnPinProg\|unix.Close' -r pkg` in the diff. For each, ask who else holds that FD. Reject `range bpfData.Maps { UnPinMap }`.

<a id="c7"></a>
### [advisory] C7. Serialize loads that share a prefix

Blocking only if: a new SDK caller loads a pod's prefix without `podIdentifierLocks` on the CNI ADD or reconcile path, which run concurrently.

**Rule.** Never run two loads with the same prefix at the same time. Concurrent loads are safe only for different prefixes and distinct global names. `RecoverGlobalMaps` must not run alongside loads that use the cache.

**Why.** The SDK does not report `BPF_OBJ_PIN` failures today, and `CreateBPFMap` discards `PinMap`'s error. Map and program IDs are then read back from the pin path, not the FD. `PinMap` / `PinProg` are check, unlink, pin sequences with no lock. With a racing same-prefix load, the returned ID can belong to the other load's object while the FD is ours. Silent. Each load also allocates a verifier log buffer of about 16 MiB.

**Cites.** SDK 9127cb7: `pkg/utils/utils.go:72-81`, `pkg/maps/loader.go:220-222`, `234-261`, `elf.go:262-268`, `352-358`, `pkg/progs/loader.go:212-240`, `pkg/utils/utils.go:209-211`. NPA 4bf96cf: per-podIdentifier lock (`pkg/ebpf/bpf_client.go:400-404`, `799-800`); recovery runs before controllers and the RPC server start (comment at `bpf_client.go:402-403`). The ct-deny probe runs in `NewBpfClient` under its own prefix, before any of them (`bpf_client.go:215`, `318`).

**Check.** For any new `LoadBpfFile*` call or new goroutine that calls the SDK: which lock or startup ordering serializes it? New code that pins directly (`PinObject`, `PinMap`, `CreateBPFMap`) must verify the pin itself, for example that the ID from `GetMapFromPinPath` equals the ID of its own FD.

<a id="c8"></a>
### [advisory] C8. `LoadBpfFile*` is not transactional

Blocking only if: the change reloads under an attached pod's prefix as a routine step, or retries a load that fails the same way each time (FDs leak per try).

**Rule.** After a failed load, treat the prefix's map pins as replaced and the FDs as leaked. Don't reload under the prefix of a live, attached program unless you will finish the swap. This holds for v1.0.19. The SDK #179 behavior below applies once NPA pins v1.0.20 or later.

**Why.** Maps are loaded and re-pinned before programs are parsed. Any later error returns `nil, nil, err`, so the caller never sees the new FDs. If the prefix belongs to an attached pod, the old program keeps its old maps, but the pins now name new empty maps. Anything that opens the map by pin (the CLI, recovery after a restart) then targets maps the datapath does not read. Silent. A retry loop leaks FDs on each failure.

SDK #179 (SDK main `62628d3`, released in v1.0.20; applies once NPA pins v1.0.20 or later) records each map and program a load creates and, when the load fails, closes them newest first. It unpins a recorded object only if the pin still holds an object with the same kernel ID, so a pin that another load replaced is kept. Maps added to the global cache are not released. The pin was already unlinked to make room for the new object, so after a failed reload under a live prefix the pins are gone rather than replaced, and the old program still runs on maps no pin names (inferred from the code, not run). The rule against reloading under a live prefix still applies.

**Cites.** SDK 9127cb7: `elf.go:1094-1110`, `pkg/progs/loader.go:357-361`, `elf.go:352-355`. SDK main 62628d3: `elf.go:144`, `325-329`, `430` (record), `elf.go:243-265` (release and ID check), `elf.go:295-300`, `1160-1165` (release on any error), `elf.go:355-356` (cached maps kept). NPA 4bf96cf: `pkg/ebpf/bpf_client.go:1177-1184`. The ct-deny probe loads under its own prefix and removes its pins by glob after the load, whether or not it succeeded (`bpf_client.go:1130-1156`, `1160-1169`); on v1.0.19 a failed probe still leaks the FDs the load created.

**Check.** For each load site: what is attached under this prefix now, and what happens if the load fails half way?

<a id="c9"></a>
### [advisory] C9. TC helpers own handle 1 on every interface that matches a prefix

Blocking only if: the change adds another tc filter with handle `0x1` on `eni*`/`vlan*`, or widens the prefix list to interfaces the agent doesn't own. A missing error check alone needs a netlink failure.

**Rule.** Nothing else may install a tc filter with handle `0x1` on these interfaces. The prefix list must not match interfaces the agent doesn't own. Callers must check `GetAllAttachedProgIds`'s error.

**Why.** Prefix match is `strings.HasPrefix`. Attach uses handle 1, priority 1. Detach deletes the first filter with handle 1 at any priority. `CleanupQdiscs` deletes filters only (never qdiscs), swallows every detach error, and returns nil unless `netlink.LinkList` fails. `getAttachedProgId` logs a `FilterList` error and reports 0, so that link is missing from the result without an error. In the upgrade path, if `GetAllAttachedProgIds` fails but `CleanupQdiscs` succeeds, filters are removed and no pod is queued for re-attach (unverified end to end). The upgrade path doesn't check this error today.

**Cites.** SDK 9127cb7: `pkg/tc/tc.go:79-89`, `122-133`, `165-175`, `269-309`, `314-317`, `340-344`. NPA 4bf96cf: prefixes `eni`, `vlan` (`pkg/ebpf/bpf_client.go:196`); upgrade path `bpf_client.go:636-640`.

**Check.** Any diff to the prefix list or the upgrade path. Any new component that adds tc filters on `eni*` or `vlan*`.

<a id="c10"></a>
### [advisory] C10. Re-attach is detach plus attach, and "file exists" is ambiguous

Blocking only if: the change enables `nl.EnableErrorMessageReporting`, or adds an attach path that leaves the hook empty with no later attach to refill it. The gap during a normal reattach is transient.

**Rule.** Replacing the program on a hook leaves it unfiltered between detach and attach. Matching `err.Error() == "file exists"` works only while `nl.EnableErrorMessageReporting` stays false process-wide.

**Why.** `FilterAdd` and `QdiscAdd` use `NLM_F_CREATE|NLM_F_EXCL`, so an existing filter or qdisc returns EEXIST (checked on np-npa-repro, AL2023 6.1.188 and AL2 5.10.245, 2026-11-03). The SDK has no replace API. During the gap the pod's traffic in that direction is not evaluated and passes. Removing the last filter sets the hook's mini-qdisc pointer to NULL, and the hook then returns the packet unchanged (Linux v6.1 `net/sched/cls_api.c:1685-1694`, `net/sched/sch_ingress.c:55-60`, `net/sched/sch_generic.c:1548-1549`, `net/core/dev.c:3945-3946` egress, `:5117-5118` ingress; same in v5.10; in v6.12 `net/core/dev.c:3996-3997` returns `TC_ACT_UNSPEC`, which also passes). On a v1.4.3 node, deleting a pod's filter from its host egress hook let through a connection its deny-all ingress policy had blocked, and nothing re-attached the filter within 100 s (checked on np-npa-repro, AL2023 6.1.188, 2026-11-03). A `QdiscList` error is treated as "not installed", so `QdiscAdd` returns EEXIST, which NPA reads as a stale filter. NPA then detaches the live filter and retries; if `QdiscList` fails again, the hook is left empty. If netlink error reporting is enabled, the kernel's extack text is appended and the string compare stops matching. With netlink v1.3.1, a duplicate `FilterAdd` returns "file exists: Filter already exists" and a duplicate `QdiscAdd` returns "file exists: Exclusivity flag on, cannot modify" (checked on np-npa-repro, AL2023 6.1.188 and AL2 5.10.245, 2026-11-03). `errors.Is(err, unix.EEXIST)` is true with reporting on or off, so prefer it.

**Cites.** SDK 9127cb7: `pkg/tc/tc.go:34-41`, `56-61`, `115-118`, `135-138`, `223`. NPA 4bf96cf: `pkg/utils/utils.go:472-477` (`IsFileExistsError`), used at `pkg/ebpf/bpf_client.go:908-916` and `953-961`. netlink v1.3.1: `filter_linux.go:304`, `qdisc_linux.go:138` (`NLM_F_EXCL`), `nl/nl_linux.go:46` (default false), `:567`, `:641` (extack wrap).

**Check.** For a new attach path: is a stale filter possible, and is the gap acceptable? If not, the SDK needs a `FilterReplace`-based API. `grep -rn EnableErrorMessageReporting .`.

<a id="c11"></a>
### [blocking] C11. `CleanupQdiscs` / `GetAllAttachedProgIds` directions depend on the SDK version

Blocking when: a caller assumes the other SDK version's direction convention, or the change alters only one direction's objects and n-1 runs SDK v1.0.18 or earlier.

**Rule.** When reviewing a caller of either function, check `go.mod`. In v1.0.19 arguments and results are pod directions. In v1.0.18 and earlier, including v1.0.17, they are host-hook directions, the opposite. The signatures are identical.

**Why.** Pod ingress is the host egress hook, because the hook is on the host-side veth (SDK comment at `tc.go:283-287`). A caller written for one convention and run against the other cleans up, or reports, the wrong direction. Silent.

**Cites.** SDK 9127cb7: `pkg/tc/tc.go:288-306` (`podIngressCleanup` calls `TCEgressDetach`), `tc.go:355-374` (pod ingress read from `HANDLE_MIN_EGRESS`). SDK v1.0.17: `pkg/tc/tc.go:283-295` (`ingressCleanup` calls `TCIngressDetach`; v1.0.18 has the same code). NPA 4bf96cf: `go.mod:8` (v1.0.19); callers at `pkg/ebpf/bpf_client.go:636-640` pass `updateIngressProbe, updateEgressProbe`; attach inversion at `bpf_client.go:908`, `953`.

**Rollback.** A rollback runs n-1's agent and n-1's SDK, not this one's. Every NPA release up to v1.4.3 runs SDK v1.0.18 or earlier (v1.4.3 pins v1.0.17), so the direction flip matters only on rollback to one of them. An upgrade from them runs this agent's v1.0.19 and cleans up the right direction. The byte compare (v1.4.3 `bpf_client.go:368-411`; the same logic at 4bf96cf `430-476`) sets an update flag only for the directions whose objects differ; an events change sets all three. With SDK v1.0.17, `CleanupQdiscs(true, false)` (pod ingress only) calls `TCIngressDetach` (v1.0.17 `tc.go:283-285`), which removes the host ingress hook's filter. That hook carries the pod egress program (`attachEgressBPFProbe` calls `TCIngressAttach`, v1.4.3 `bpf_client.go:873`; 4bf96cf `:953`). So a change to only one direction's objects makes a rollback to an agent on v1.0.18 or earlier remove the other direction's filters. To make the transition change both directions, bump `NPA_FILE_VERSION` in all four tc programs ([P2](#p-change)), as #704 did for the ct-deny change (commit `dcdb537`). Whether the removed filters are re-attached depends on the pod. In a strict-mode test, an ingress-only change rolled back to v1.4.3 removed the host ingress filter (the pod egress program) on both test pods. The policy pod's filter came back within one 13 s sample with the same program ID. The no-policy pod's filter stayed missing for the 3.5 minutes observed (checked on np-npa-repro, AL2023 6.1.188, 2026-10-27). That pod's egress still failed, likely because its default-deny ingress program drops the reply (inferred). Standard mode was not tested (unverified).

**Check.** `grep -n aws-ebpf-sdk-go go.mod` with any diff near these calls. An SDK bump changes upgrade behavior here; say so in the PR. For a one-direction change, name the n-1 versions that are safe rollback targets.

<a id="c12"></a>
### [blocking] C12. Map key and value buffers must match the map's sizes exactly

Blocking when: a Go key or value type differs from the C `key_size` / `value_size`, or its padding differs from the C struct.

**Rule.** Pointers passed to map APIs must reference at least `KeySize` / `ValueSize` bytes. Go mirrors of C structs must have the same size and padding.

**Why.** The SDK passes raw `uintptr`s with no size check. A short buffer makes the kernel read or write adjacent Go memory: the syscall copies exactly `key_size` bytes of key and `value_size` bytes of value from the pointer, and writes `value_size` bytes back on lookup (Linux v6.1 `kernel/bpf/syscall.c:1283-1303`, `:1340`, `:1366`, `:1413`, `:1419-1420`; same in v5.10 and v6.12). Per-CPU maps copy `round_up(value_size, 8) * num_possible_cpus()` (`:154-165`), and NPA uses none. Silent. A key whose padding bytes are not zeroed hashes differently: hash and LRU hash maps `jhash` and `memcmp` all `key_size` bytes (`kernel/bpf/hashtab.c:600-603`, `:623`, `:642`, `:666-672`, `:1086-1088`, `:1188-1190`), which is why the C code memsets keys before filling them.

**Cites.** SDK 9127cb7: `pkg/maps/loader.go:296-326`, `418-439`. NPA 4bf96cf: `pkg/utils/utils.go:28-31` (trie sizes), `utils.go:544-573` (`ConntrackKey` and `ConntrackKeyV6` with explicit `_` padding, `ConntrackVal`), `pkg/ebpf/bpf_client.go:124-126` (`pod_state`), `pkg/ebpf/c/tc.v4ingress.bpf.c:336,338` (memset). Shape tests: `pkg/ebpf/conntrack/conntrack_client_test.go:44-63` (key field names only, not sizes); `:67-77` checks `ConntrackVal` size and offset against a hard-coded 16, not against the C object.

**Check.** For any struct or constant change on either side of a map, compare the Go size with the C `key_size` / `value_size`. A privileged test that loads each ELF and compares `GetBPFmapInfo(fd).KeySize/ValueSize` with the Go sizes catches drift.

<a id="c13"></a>
### [advisory] C13. Map API return semantics

Blocking only if: the change relies on `CreateMapEntry` to replace a policy, pod-state or conntrack value. A not-found branch that never fires only takes the generic error path.

**Rule.**

- `errors.Is(err, unix.ENOENT)` works after `GetNextMapEntry`, `GetFirstMapEntry`, `GetNextMapEntryByID` and `GetFirstMapEntryByID` (and for a missing pin after `GetMapFromPinPath`). The other entry APIs (lookup, update, delete) stringify the errno with `%s`.
- `CreateMapEntry` (`BPF_NOEXIST`) returns nil when the key already exists. It never overwrites.
- The SDK bulk APIs are not atomic: `BulkUpdateMapEntry` stops at the first failure with earlier entries already written, and `BulkRefreshMapEntries` only logs delete failures. NPA does not use them.

**Why.** An ENOENT check after a lookup never fires, so the not-found path becomes the generic error path. A caller that expects `CreateMapEntry` to set a value keeps the old one. Both silent.

**Cites.** SDK 9127cb7: `pkg/maps/loader.go:369-371`, `654-656` (bare errno), `432-434`, `687-689`, `319-321`, `341-343` (stringified), `314-317` (EEXIST), `453-498` (bulk). NPA 4bf96cf: relies on `CreateMapEntry` for idempotency (`pkg/ebpf/bpf_client.go:1389-1406`); has its own shadow map (`pkg/ebpf/bpf_mem_map.go:91-143`). Existing ENOENT checks are not a precedent to copy: for example `conntrack_client.go:104` and `:276` follow `GetMapEntryByID` and never match.

**Check.** `grep -n 'errors.Is(err, unix.ENOENT)' -r pkg`: the preceding call must be a next-key API. Reject new uses of the SDK bulk APIs.

<a id="c14"></a>
### [blocking] C14. ELF map definitions: 28-byte layout, `PIN_GLOBAL_NS` only

Blocking when: the change edits `struct bpf_map_def_pvt` or adds a map whose `.pinning` is not `PIN_GLOBAL_NS`.

**Rule.** `SEC("maps")` entries must be 7 consecutive `__u32`: type, key_size, value_size, max_entries, map_flags, **pinning**, inner_map_fd. Every map a pinned program references must use `PIN_GLOBAL_NS`. Expect every load to replace the map with a new, empty one.

**Why.** The SDK strides by 28 bytes and reads pinning from bytes 20-24. libbpf's 20-byte `bpf_map_def` or iproute2's `bpf_elf_map` (sizes per their headers, not in these trees) are misread: usually the loader panics with a slice out of range, and for some map counts it misparses silently. The loop panics whenever the section leaves fewer than 24 bytes after the last 28-byte stride. Only `PIN_GLOBAL_NS` pins, and it unlinks any existing pin first. Pin types 1 and 3 are not pinned, so the same load then fails with "map ... doesn't exist" (`elf.go:263-266`). `PIN_NONE` maps have no pin, so recovery aborts the whole walk.

**Cites.** SDK 9127cb7: `elf.go:43`, `elf.go:487-497`, `pkg/maps/loader.go:226-265`, `elf.go:256-276`, `1348-1362`. The Go struct `BpfMapDef` names the 6th and 7th fields the other way round (`pkg/maps/loader.go:66-74`); the parser is what counts. NPA 4bf96cf: `struct bpf_map_def_pvt` at `pkg/ebpf/c/tc.v4ingress.bpf.c:47-55`, `pkg/ebpf/c/v4events.bpf.c:6-14`; `.pinning = PIN_GLOBAL_NS` at `tc.v4ingress.bpf.c:114,123,136`.

**Check.** `grep -n 'struct bpf_map_def_pvt {' -A8 pkg/ebpf/c/*.c` and `grep -n '\.pinning' pkg/ebpf/c/*.c`.

<a id="c15"></a>
### [blocking] C15. No CO-RE, BTF-defined maps, or global data

Blocking when: BPF code dereferences a kernel-internal struct field, or adds a global variable, `bpf_printk`, `SEC(".maps")` or `BPF_CORE_READ`.

**Rule.** BPF C may reference only maps in its own `SEC("maps")` or globals already in the cache. Do not read kernel-internal struct fields. Only UAPI-stable layouts (`__sk_buff`, IP and TCP headers) are safe. Do not use global variables, `bpf_printk`, `SEC(".maps")` or `BPF_CORE_READ`.

**Why.** Relocation resolves a symbol by name only: local map, then cache. The SDK has no handling of `.BTF.ext`, `.maps`, `.data`, `.rodata` or `.bss`, and passes no program BTF to `BPF_PROG_LOAD`. A CO-RE field access (anything through `vmlinux.h`, unverified: depends on bpftool's `preserve_access_index` output) loads with its compile-time offset. On a kernel whose layout differs it reads another field (unverified: the verifier allows it). Silent. Global variables and `.maps` maps fail the load (observable).

**Cites.** SDK 9127cb7: `elf.go:717-736`, `pkg/progs/loader.go:293-343`. NPA 4bf96cf: TC C includes `vmlinux.h` (`pkg/ebpf/c/tc.v4ingress.bpf.c:1`) but touches only UAPI structs. The ct-deny code passes `struct nf_conn` to kfuncs only as an opaque pointer and declares its own `bpf_ct_opts` layout instead of reading it from BTF (`pkg/ebpf/c/ct_deny.h:39-57`, `81-88`). `NPA_FILE_VERSION` (`tc.v4ingress.bpf.c:494`) is a `const volatile` global that no code references; referencing it would need `.rodata` support (unverified).

**Check.** In a `.c` / `.h` diff, grep `->` on pointers from kfuncs or helpers that point into kernel memory, and grep for global non-map variables, `bpf_printk`, `SEC(".maps")`, `BPF_CORE_READ`. Pass kernel objects such as `struct nf_conn` only as opaque pointers to kfuncs.

<a id="c16"></a>
### [blocking] C16. Program sections and `.text` subprograms

Blocking when: a program uses a section outside the SDK's set, a program function is renamed without its `TC_*_PROG` constant, or a kfunc is called from a `.text` subprogram.

**Rule.** Program sections must be `xdp`, `tc_cls`, `tc_act`, `kprobe/<fn>`, `kretprobe/<fn>` or `tracepoint/<subsys>/<name>`. Each program must be a GLOBAL function, and the function name must match the constant NPA uses to rebuild the pin path. An ELF with `.text` subprograms must have one entry function that owns its whole section. Subprograms must be static `__noinline`. kfuncs must be called from the program section, so helpers that call kfuncs must be `__always_inline`.

**Why.** An unsupported section type is skipped with an Info log, so `SEC("tc")` or `SEC("classifier")` loads "successfully" with zero programs. Static functions in program sections are not loaded. The `.text` rules fail at load time only, so only a test that loads the built ELF catches them.

**Cites.** SDK 9127cb7: `elf.go:419-434`, `982-984`, `1047-1051`, `928-935`, `1034-1037`, `682-685`, `561-563` (kfunc from `.text`). NPA 4bf96cf: `SEC("tc_cls")` (`pkg/ebpf/c/tc.v4ingress.bpf.c:322`); `utils.TC_INGRESS_PROG` / `TC_EGRESS_PROG` (`pkg/utils/utils.go:35-36`); pin path rebuilt at `utils.go:219-226`; missing program caught at `pkg/ebpf/bpf_client.go:1188-1193`. The kfunc helpers in `pkg/ebpf/c/ct_deny.h` are all `static __always_inline` (`:68`, `98`, `110`, `128`, `143`).

**Check.** `grep -n 'SEC(' pkg/ebpf/c/*.c`. A function rename must update `TC_*_PROG`.

<a id="c17"></a>
### [advisory] C17. kfunc resolution (SDK v1.0.18 and later)

Blocking only if: the object is chosen after startup or per pod with no fallback, so a kfunc load failure leaves pods unattached on every retry. A module reload that breaks loads until restart is an unusual precondition.

**Rule.** Call `btf.CheckKfuncs` once at startup, not per load. Decide what the agent does if a later load of a kfunc-using ELF fails.

**Why.** Resolution is by name only (vmlinux first, then the first module that has it), with no prototype check. The resolver is process-wide. Module BTF FDs stay open for the process lifetime, so after a module such as `nf_conntrack` is unloaded and reloaded, kfunc programs fail to load until the agent restarts (per the SDK comment at `kernel.go:57-59`; kernel behavior unverified). Only successes are cached. Each failed check re-walks all kernel BTF while holding the resolver's mutex, so any concurrent kfunc-using load waits for that walk.

**Cites.** SDK 9127cb7: `pkg/internal/btf/kernel.go:55-65`, `82-115`, `137-178`, `pkg/btf/btf.go:23-33`. NPA 4bf96cf calls `CheckKfuncs` once per start, for the three conntrack kfuncs the ct-deny objects call (`pkg/ebpf/bpf_client.go:74`), in `chooseIngressBinary` (`:1105`), through a variable tests replace (`:76-78`). After startup there is no fallback: a later load failure of the chosen object fails that pod's attach like any other load (`:898-901`, `1177-1184`). v1.0.17 has no kfunc support.

A `CheckKfuncs` error of the form `read BTF ID <n>: <errno>` comes from the walk over kernel BTF objects (`pkg/internal/btf/kernel.go:244-249`), not from the verifier. A failed program load returns only the errno; the verifier's reason is only in the SDK log ([C19](#c19)).

**Check.** Where is `CheckKfuncs` called, and how often? Is the decision made once at init, logged, and visible (see [P9](#p-gate))? When a kfunc load fails, read the SDK log before concluding why.

<a id="c18"></a>
### [advisory] C18. Ring buffer: one map per `Events`, keep draining

**Rule.** Call `InitRingBuffer` once per process per ring buffer map, with a single FD. Drain the returned channel continuously.

**Why.** With several FDs, each ring overwrites the shared channel fields, so earlier channels never receive. Silent. The channel is unbuffered. A slow consumer blocks the reader and the ring fills. A full ring keeps its unread records and rejects the new one: `bpf_ringbuf_output` returns `-EAGAIN` without writing it, and the kernel keeps no drop count (Linux v6.1 `kernel/bpf/ringbuf.c:416-422`, `:520-522`; same in v5.10 and v6.12). NPA ignores the return, so events are lost silently. There is no public stop.

**Cites.** SDK 9127cb7: `pkg/events/events.go:153-158`, `161`, `234`. NPA 4bf96cf: one FD (`pkg/ebpf/events/events.go:99-102`); C ignores the output result (`pkg/ebpf/c/tc.v4ingress.bpf.c:420-423`).

**Check.** Exactly one `InitRingBuffer` call. No new blocking work in the receive loop. The existing loop already calls `PutLogEvents` synchronously when CloudWatch logs are enabled (`pkg/ebpf/events/events.go:197`, `:283`); don't add to it.

<a id="c19"></a>
### [advisory] C19. Some failures appear only in the SDK's own log

**Rule.** When diagnosing SDK behavior, read `/var/log/aws-routed-eni/ebpf-sdk.log` (or `$AWS_EBPF_SDK_LOG_FILE`) as well as the agent log. SDK errors do not carry verifier output.

**Why.** Log-only failures: pin syscall failures, `CleanupQdiscs` detach errors (only `FILTER_CLEANUP_FAILED` is logged; others are dropped), per-link `FilterList` errors, map close failures, and module BTF parse failures (log-only when the kfunc is found elsewhere; included in the error when it is not). The verifier log is logged at Info; the returned error carries only the errno. Some recovery errors carry no context ("failed to get err", "unable to get FD").

**Cites.** SDK 9127cb7: `pkg/logger/logger.go:28-31`, `pkg/progs/loader.go:347-353`, `pkg/tc/tc.go:290-306`, `314-317`, `pkg/internal/btf/kernel.go:157`, `186-187`, `elf.go:1346`, `1361`, `1508`, `pkg/utils/utils.go:72-83` (pin errno never returned), `pkg/maps/loader.go:221` (`PinMap` result dropped), `loader.go:622-625` (map close). NPA 4bf96cf: `sdkAPIErr` labels (`pkg/ebpf/bpf_client.go:93-99`) cannot see these cases.

**Check.** For a new failure mode, ask which log line or metric shows it in production. If only the SDK log, say so in the PR.

<a id="c20"></a>
### [advisory] C20. Fixed bpffs paths are duplicated in NPA

**Rule.** `/sys/fs/bpf/` must be a bpffs mount. Nothing may change the SDK's `PROG_BPF_FS` / `MAP_BPF_FS` without changing NPA's copies and its index-based parser.

**Why.** Only the recovery and walk APIs (`RecoverGlobalMaps`, `RecoverAllBpfProgramsAndMaps`, `GetAllBpfProgramsAndMaps`) check the bpffs magic. The load path just creates directories, so without bpffs the pins fail: `BPF_OBJ_PIN` returns `EPERM` when the pin's parent directory is not a bpffs directory (Linux v6.1 `kernel/bpf/inode.c:457-461`; same in v5.10 and v6.12). The SDK does not report it (see [C7](#c7)), and the same load fails with "map ... doesn't exist". A change in path depth breaks `pinPathName[7]`.

**Cites.** SDK 9127cb7: `pkg/constants/constants.go:92-94`, `111-112`, `elf.go:1170`, `1257`, `1428`. NPA 4bf96cf: `pkg/utils/utils.go:33-34`, `207-217` (`[7]`); `pkg/ebpf/bpf_client.go:51-52` (`CONNTRACK_MAP_PIN_PATH`, `POLICY_EVENTS_MAP_PIN_PATH`), compared literally at `bpf_client.go:512-521`; also `pkg/ebpf/events/events.go:30`, `pkg/ebpf/conntrack/conntrack_client.go:16`, `pkg/ebpf/healthcheck.go:25`.

**Check.** `grep -rn '/sys/fs/bpf' pkg` in the diff, and any SDK bump that touches `constants.go`.

<a id="c21"></a>
### [blocking] C21. Unpin and close do not detach a tc filter

Blocking when: a failure path unpins or closes a program that an attached filter still runs without detaching that filter, or unloads a program that was already in the context.

**Rule.** A tc filter keeps running its program after the program's pin is removed and its FD is closed. On a failure path, never unpin or close a program that a filter on a live veth still references, unless you also detach that filter. A rollback in `AttacheBPFProbes` must:

- Run under `podIdentifierLocks`. Register its `defer` after the `Unlock` defer, so it runs first (LIFO).
- Unload only programs this call loaded. Keep any program that was already in the context: other pods of the identifier share it, and `recoverBPFState` may have restored it.
- For a direction this call already attached on some veth, either detach it there or keep its program pinned and in the context.

**Why.** `UnPinProg` and `UnPinMap` unlink the pin and close the FD. Neither touches tc; detach is a separate API. The kernel keeps a program alive while a filter references it. The `cls_bpf` filter takes its own reference on the program at attach and drops it only when the filter is deleted; unlinking the pin and closing an FD each drop only their own reference (Linux v6.1 `net/sched/cls_bpf.c:385`, `:399`, `:256-260`; `kernel/bpf/syscall.c:2059-2073`, `:2082-2087`; `kernel/bpf/inode.c:613-621`; same in v5.10 and v6.12). The program also holds its maps (`kernel/bpf/verifier.c:12898-12906`), so the filter keeps reading the same, now unreachable, `*_pod_state_map`. A program with no pin and no open FD kept dropping packets while its filter was attached and was freed when the filter was deleted (checked on np-npa-repro, AL2023 6.1.188 and AL2 5.10.245, 2026-11-03). A freshly loaded program's `*_pod_state_map` is empty, and every tc program drops a packet when either pod-state key is missing. Pod state is written only after the attach. The CNI ADD writes it after `AttacheBPFProbes` returns nil. The reconcilers write it in the same pass, but only if `HasBPFContext` is true.

So if a rollback unloads a program after one direction, or an earlier veth, already attached, that filter drops every packet in that direction, and nothing can program it. With the context gone, map and pod-state updates return "no bpf context registered" and the reconciler skips programming. With the pins gone, the CLI and `recoverBPFState` can't find it. The drop lasts until a later attach replaces the filter through the stale-filter path ([C10](#c10)) (inferred, not run).

At 4bf96cf there is no rollback. (#715, merged after 4bf96cf as `0c49457`, adds one; see the example below.) A failed attach returns at the first error. A direction already attached stays attached, and its program stays pinned and in the context. Its pod state stays empty until the next write: the reconciler writes it in the same pass if the context exists, even when the attach errored; after a failed CNI ADD it waits for the reconciler. So at 4bf96cf, a partially attached direction drops until the next write. A rollback that unpins without detaching makes that window unbounded.

**Cites.** SDK 9127cb7: `pkg/progs/loader.go:243-260` (`UnPinProg`), `pkg/maps/loader.go:268-286` (`UnPinMap`), `pkg/tc/tc.go:36-38`, `143`, `231` (separate `TCIngressDetach` / `TCEgressDetach`). NPA 4bf96cf:

- Lock and early returns: `pkg/ebpf/bpf_client.go:799-800`, `844-848`, `857-861`. Lock comment: `:400-404`.
- Program kept in context when loaded: `bpf_client.go:893-905`, `938-950`. Unpin without detach: `:1026-1070`.
- Drop on missing pod state: `pkg/ebpf/c/tc.v4ingress.bpf.c:416-427`, `tc.v4egress.bpf.c:432-440`.
- State written after the attach: `pkg/rpc/rpc_handler.go:85-90` and `:143-170`; `controllers/policyendpoints_controller.go:454-466` (skips programming without a context) and `:657-670`.
- "no bpf context registered": `bpf_client.go:1230`, `1426`.

Example: [#715](https://github.com/aws/aws-network-policy-agent/pull/715) added such a rollback. It merged on 2026-11-02 as `0c49457`, after this guide's pin `4bf96cf`, so the lines below are at `0c49457`. Its `pkg/ebpf/bpf_client.go` is unchanged from the change commit `5558fd6`.

- `pkg/ebpf/bpf_client.go:808-809`: the lock and its `Unlock` defer.
- `bpf_client.go:822-831`: the rollback defer, registered after the `Unlock` defer.
- `bpf_client.go:929-932`: an existing program is reported as not loaded.
- `bpf_client.go:1209-1236`: `unloadBPFProgram`. Its comment says "It does not detach the TC filter".

**Check.** For each unpin, unload or close on an error path, ask which filters reference the program now. Is the rollback's `defer` after the lock's? Is each direction it unloads one that this call loaded? Does a unit test cover a failure after the first attach, with the strict TC mock asserting what stays attached?

<a id="parity"></a>
## 4. v4/v6 parity

The only shared header is `pkg/ebpf/c/ct_deny.h`, included by both ingress programs (`tc.v4ingress.bpf.c:5`, `tc.v6ingress.bpf.c:5`). It defines `_v4` / `_v6` function pairs, and its code is compiled only into the ct-deny objects. `helper.h` exists but nothing includes it. There is almost no shared Go code between families. The `pkg/ebpf` unit tests mostly exercise v4 (rule processing and the CIDR trie do have v6 unit tests): `NewMockBpfClient` hard-codes `hostMask: "/32"` (`pkg/ebpf/bpf_client_mock.go:13-24`). The only unit tests that use a v6 constant check the ct-deny binary choice and compare (`TC_V6_INGRESS_CT_DENY_BINARY`, `pkg/ebpf/bpf_client_test.go:1837`, `1983-1984`). No unit test calls `EVENTS_V6_BINARY`, `MapWalkv6` or `Cleanupv6ConntrackMap` (the v6 key has only a field-name shape test, `conntrack_client_test.go:55`). An IPv6 integration run is the only check for most v6 paths.

<a id="parity-table"></a>
### What must change together (NPA 4bf96cf)

| Area | v4 | v6 | Keep in sync |
|---|---|---|---|
| TC programs | `pkg/ebpf/c/tc.v4ingress.bpf.c`, `tc.v4egress.bpf.c` | `tc.v6ingress.bpf.c`, `tc.v6egress.bpf.c` | Whole program, `NPA_FILE_VERSION`. The ingress sources also build the ct-deny objects (`-DNPA_CT_SHORTEN_ON_DENY`, `Makefile:173-174`), so the `#ifdef NPA_CT_SHORTEN_ON_DENY` blocks (`tc.v4ingress.bpf.c:424-426`, `451-456`, `483-488`; `tc.v6ingress.bpf.c:429-431`, `458-463`, `489-494`) and the `shorten_denied_*_v4` / `_v6` pairs in `ct_deny.h:98-155` must match too |
| Events programs | `pkg/ebpf/c/v4events.bpf.c` | `v6events.bpf.c` | Define `aws_conntrack_map` (key size comes from this file) and `policy_events` |
| `struct conntrack_key` | `tc.v4ingress.bpf.c:81-89`, `tc.v4egress.bpf.c:81-89`, `v4events.bpf.c:31-39` | `tc.v6ingress.bpf.c:81-89`, `tc.v6egress.bpf.c:81-89`, `v6events.bpf.c:32-40` | Go: `pkg/utils/utils.go:544-566` |
| `struct conntrack_value` | four tc files, both events files | same | Go: `utils.go:568-573` |
| `struct data_t` (ring record) | four tc files, both events files | same | Go: `pkg/ebpf/events/events.go:67-89` |
| Trie key and value | `__u32 ip` / `__u8 ip[4]` | `__u8 ip[16]` | `MAX_PORT_PROTOCOL 24` in all four tc files; Go `utils.go:28-31` (`TRIE_VALUE_LENGTH` depends on it), `605-613` |
| Binary and CLI names | `pkg/ebpf/bpf_client.go:38-50`, `69-70` (ct-deny) | same | `pkg/utils/cp/cp.go:11-14` duplicates the CLI names; `cp.go:22-26` maps the v6 CLI and both ct-deny objects to their host names |
| Family selection | `bpf_client.go:186-191`; ingress variant from `ingressBinaries` (`:1073-1078`) | same | A second events switch at `bpf_client.go:262-265` |
| Change detection | `bpf_client.go:435`, `456`, `464-465`, `469` | same | Each name check lists both families, and the ingress check both variants |
| Conntrack GC | `pkg/ebpf/conntrack/conntrack_client.go:79-246` | `:248-423` | v4 compares through `ConvIPv4ToInt(ConvIntToIPv4(x))`; v6 compares raw bytes |
| Event decode and log text | `pkg/ebpf/events/events.go:220-277` | same | Both formats. The two Flow Info formats already differ in punctuation (`events.go:241` vs `270`); keep a change from widening that |
| CLI | `pkg/clihelper/show.go:155-314`, `cmd/cli/` | `show.go:317-442`, `cmd/cliv6/` | v6 is a subset today |
| Rule processing | `pkg/fwruleprocessor/fw_rule_processor.go`, `cidr_trie.go:12-42` | same | `hostMask`, `shouldSkipRule`, v4-mapped v6 |
| Catch-all entry | `controllers/policyendpoints_controller.go:803-815` (`0.0.0.0/0`) | `::/0` | Only the PE reconciler takes `enableIPv6` |
| Conversion helpers | `pkg/utils/utils.go:516-532` | `utils.go:534-542`, `585-603`, `628-640` | `ConvTrieV6ToByte` hard-codes `*[20]byte` |
| Build and image | `Makefile:124-125`, `147-174`, `Dockerfile:53-62` | same | Both CLIs, all eight `.o` files (six tc, two events) |
| Integration tests | `--ip-family` (`test/framework/options.go:36`) | `curl -6` in `ValidateConnection` (`test/framework/resources/k8s/pod/resource.go:245`) | Per-family targets and host masks |

Expected family-specific behavior at 4bf96cf: v6 ingress and egress let ICMPv6, and Hop-by-Hop followed by ICMPv6, through unconditionally (`tc.v6ingress.bpf.c:358-369`, `tc.v6egress.bpf.c:368-379`). Expected direction differences within one family: map names, `handle_ingress` / `handle_egress`, trie key from `saddr` (ingress) or `daddr` (egress), `owner_ip`, `is_egress`, the egress-only `baseline_tier_priority` out-param of `evaluateClusterPolicyByLookUp`, `effective_action`, the unused `NETWORK_POLICY_TIER_PRIORITY`, the dead `dest_ip` / `src_ip` local in the v4 files, the ingress `verdict` local returned after the last `NPA_CT_SHORTEN_ON_DENY` block (egress returns `evaluateFlow` directly), and, in ingress only, the `ct_deny.h` include and the three `NPA_CT_SHORTEN_ON_DENY` blocks.

<a id="parity-diff"></a>
### Running the diff helper

`hack/v4v6-diff.py` diffs the C sources by family. Run the commands from the NPA root. It strips comments and whitespace, rewrites family tokens to a common form, and diffs each object pair the Makefile builds. The ingress sources are diffed twice: as the regular objects, and with `-DNPA_CT_SHORTEN_ON_DENY` as the ct-deny objects. For each pair the helper resolves `#ifdef` / `#ifndef` / `#else` / `#endif` on that macro as the build does and blanks the dropped lines, so line numbers still match the source. In pair mode it diffs the regular objects unless given `-DNPA_CT_SHORTEN_ON_DENY`. Identifiers ending in the file's own suffix (`_v4` in v4 files, `_v6` in v6 files) are rewritten to `_vX`, so family-named helpers and their call sites match, and a call to the other family's helper shows as a hunk. The L4 protocol rewrite equates `ip->protocol` with `ip->nexthdr`, and in v6 the next header can be an extension header, so check v6 extension-header handling by reading, not by the diff. The port-width rewrite equates `__u16` and `__u32` ports, so a width change does not show either. The trie key fill (four byte stores in v4, a 16-byte loop in v6) collapses to one token only when it has exactly the expected shape; any other edit there shows as a hunk. Hunks carry original line numbers on both sides.

Code shared by both families in one header is not in a file pair. `--funcs` diffs each `foo_v4` / `foo_v6` function pair defined in one file and reports a function without its twin. `--all` runs it on every `pkg/ebpf/c/*.h` except `vmlinux.h`; a header with no such functions prints nothing. `--funcs` does not resolve macros. It finds definitions whose name is on the first line of the signature.

```bash
# Every object pair (regular ingress, ct-deny ingress, egress, events), then the _v4/_v6 functions in every header
python3 -I hack/v4v6-diff.py --all .

# One pair, as the regular objects
python3 -I hack/v4v6-diff.py pkg/ebpf/c/tc.v4ingress.bpf.c pkg/ebpf/c/tc.v6ingress.bpf.c

# The same pair, as the ct-deny objects
python3 -I hack/v4v6-diff.py -DNPA_CT_SHORTEN_ON_DENY pkg/ebpf/c/tc.v4ingress.bpf.c pkg/ebpf/c/tc.v6ingress.bpf.c

# _v4/_v6 function pairs inside one file
python3 -I hack/v4v6-diff.py --funcs pkg/ebpf/c/<header>.h

# What did the change add to the v4/v6 delta?
# Extract both trees without writing to the repository (upstream = aws/aws-network-policy-agent).
mkdir -p /tmp/v4v6/base /tmp/v4v6/head
git archive "$(git merge-base upstream/main HEAD)" pkg/ebpf/c | tar -x -C /tmp/v4v6/base
git archive HEAD pkg/ebpf/c | tar -x -C /tmp/v4v6/head
diff <(python3 -I hack/v4v6-diff.py --all --no-lines /tmp/v4v6/base) \
     <(python3 -I hack/v4v6-diff.py --all --no-lines /tmp/v4v6/head)

# Direction parity within one family
diff -w pkg/ebpf/c/tc.v4ingress.bpf.c pkg/ebpf/c/tc.v4egress.bpf.c

# Struct copies and version markers
grep -n -A9 '^struct conntrack_key {' pkg/ebpf/c/*.bpf.c
grep -n 'NPA_FILE_VERSION' pkg/ebpf/c/*.bpf.c
```

At 4bf96cf the events pair has no remaining hunks. The regular and the ct-deny ingress pairs each have the same 12 baseline hunks, and the egress pair 14:

- Both directions: the ICMPv6 bypass (the only family difference left after normalization; the normalization also equates `ip->protocol` with `ip->nexthdr`, which in v6 can be an extension header); the dead v4 local (`dest_ip[4]` in ingress, `src_ip[4]` in egress), its memset and byte fill; reorders of `struct data_t evt`, `flow_key.dest_ip`, `evt.dest_ip` and `reverse_flow_key.dest_ip`.
- Ingress: the duplicate v6 conntrack lookup (`tc.v6ingress.bpf.c:438`, `441`).
- Egress: two hunks where v4 switches on `effective_action` and v6 switches on `admin_tier_action` or `baseline_tier_action`.
- `ct_deny.h`: 3 hunks, two in `shorten_denied_ct_vX` (the address parameter types, and the tuple fill: assignment or `__builtin_memcpy`, `tuple.ipv4` or `tuple.ipv6`, and the `sizeof` passed to `shorten_ct`) and one in `shorten_denied_syn_vX` (addresses passed by value or by pointer).

A change should add no new hunk unless the PR says why it is family-specific. Diff against the merge base, as above, to separate new hunks from these. In a `--funcs` hunk, expect only address types and copies (`__be32` against `struct in6_addr *`, assignment against `__builtin_memcpy`, `tuple.ipv4` against `tuple.ipv6` and its `sizeof`, `ip->saddr` against `&ip->saddr`). Known noise: a reordered statement appears as a paired insert and delete of the same text, and a lone `}` can join a neighboring hunk.

<a id="precedents"></a>
## 5. Precedents

Use the existing mechanism before adding a new one. All citations are NPA 4bf96cf.

<a id="p-hostname"></a>
### [advisory] P1. One host name for a variant binary

Blocking only if: a rollback or variant switch then skips a reload it needs because the compare reads a stale host copy (inferred).

`InstallBPFBinaries` installs each binary under `HostBinaryName(plugin)` (`pkg/utils/cp/cp.go:28-34`, `88-101`). `hostBinaryNames` maps the v6 CLI to the v4 name, and each ct-deny ingress object to the regular ingress name, for example `tc.v4ingress.ctdeny.bpf.o` to `tc.v4ingress.bpf.o` (`cp.go:22-26`). The byte compare reads the host copy under the same name (`pkg/ebpf/bpf_client.go:447`). Inside the container each binary keeps its own name (`Dockerfile:53-62`). Host-side tests always call `/opt/cni/bin/aws-eks-na-cli` (`test/integration/restart/conntrack_map_restart_test.go:175`). Tests that exec inside the container must pick the name by family.

For a new object variant, add it to `hostBinaryNames` so the selected object installs under the existing name, and to the name checks in `checkAndUpdateBPFBinaries` (`bpf_client.go:456-472`), as the ct-deny objects are. The byte compare in [P2](#p-change) then handles upgrade, downgrade and a switch between variants.

<a id="p-change"></a>
### [advisory] P2. Change detection: byte compare and `NPA_FILE_VERSION`

Blocking only if: a new object is missing from `bpfBinaries`, `build-bpf`, the `Dockerfile` or the name checks, or only one direction's objects change and n-1 runs SDK v1.0.18 or earlier ([C11](#c11)).

- `checkAndUpdateBPFBinaries` compares each shipped file in the container CWD with the host copy in `/host/opt/cni/bin/`, read under its host name ([P1](#p-hostname)): `cmp.Equal(currentProbe, existingProbe)` (`pkg/ebpf/bpf_client.go:430-476`). There is no version ID. Read errors are only logged.
- `NewBpfClient` compares the events binary on its own first (`bpf_client.go:214`). A change sets all three update flags (`:229-231`). Global-map recovery is then skipped (`bpf_client.go:499`) and every pod is reattached with default state (`bpf_client.go:665-712`).
- CLIs are excluded from the compare (`bpf_client.go:435-437`).
- Install runs after the compare: copy to `<dst>.tmp`, then rename (`pkg/utils/cp/cp.go:65-86`, called at `bpf_client.go:235` after the compares at `:214` and `:223`). Install errors are logged per file. If the deferred ct-deny probe fails, the regular ingress object is installed again over the host copy (`:318-324`).
- To force a reload without a logic change, bump `const volatile __u32 NPA_FILE_VERSION` in all four tc programs (`tc.v4ingress.bpf.c:494`, `tc.v4egress.bpf.c:494`, `tc.v6ingress.bpf.c:500`, `tc.v6egress.bpf.c:492`; added in commit `e51dfe8` "bump eBPF file version", bumped to 3 in `dcdb537`). No Go code reads it: it exists to change the object bytes so that nodes reload. It was added in [#576](https://github.com/aws/aws-network-policy-agent/pull/576) after a reviewer noted the PR had no BPF binary change and asked whether an upgrade would re-attach the probes ([review comment](https://github.com/aws/aws-network-policy-agent/pull/576#discussion_r3353563177)); the author then posted hashes showing the objects differ ([comment](https://github.com/aws/aws-network-policy-agent/pull/576#issuecomment-4637613410)). The events files do not have it.
- The agent loads objects by bare filename from the container CWD (`bpf_client.go:440`, `1133`, `1177`). A new object must be in `bpfBinaries` (`bpf_client.go:219`), `Makefile` `build-bpf` (`:166-174`), `Dockerfile` `COPY` (`:55-62`), and the name checks at `bpf_client.go:435-472`. If a file is missing from both the image and the host, both reads return nil, `cmp.Equal` reports equal, and no reload is triggered; the later `LoadBpfFile` then fails.
- An edit to a BPF C file that changes code or shifts line numbers changes the object's bytes, even when the program's logic does not change. The objects are built with `-g` (`Makefile:166-174`) and shipped unstripped (`Dockerfile:55-62`). Adding one comment line near the top of `tc.v4ingress.bpf.c` leaves the `tc_cls` instructions and `.BTF` identical but changes `.BTF.ext`, `.debug_info` and `.debug_line` in `tc.v4ingress.bpf.o` and `tc.v4ingress.ctdeny.bpf.o`; the other six objects are unchanged. A comment reworded in place, or appended at the end of the file, leaves every object byte-identical. Rebuilding unchanged source at the same path is byte-identical. (All checked by building 4bf96cf with the `build-bpf` flags, clang 15.0.7 on AL2023, 2026-11-03.) An `#include`, a moved line or a new local has the same effect as an added line, and a new type or function also changes `.BTF` (inferred). Treat any edit as changing the bytes unless you have checked (next item). Every node reloads a changed object on upgrade: each pod's program in that direction is detached and re-attached ([C10](#c10)), and that direction's pod state is set to the mode default (`bpf_client.go:665-712`, [P10](#p-mode)). Say so in the PR.
- To check, build the objects at the merge base and at the change with `make build-bpf`, then `cmp` each `.o`. Build both in the same directory path: the object also records the build directory, so the same source built in two directories differs (inferred: DWARF `DW_AT_comp_dir`). `make build-bpf` needs `pkg/ebpf/c/vmlinux.h`, which `make vmlinuxh` generates on a Linux host with `bpftool` (`Makefile:139-140`).
- If only one direction's objects change, a rollback to an agent on SDK v1.0.18 or earlier (every NPA release up to v1.4.3) removes the other direction's filters ([C11](#c11)). When that matters, bump `NPA_FILE_VERSION` in all four tc programs so both directions are reloaded, as in commits `e51dfe8` and `dcdb537`.
- A new header in `pkg/ebpf/c/` is ignored by `.gitignore` (`*.h`, line 3). It needs a `!pkg/ebpf/c/<name>.h` exception, as `ct_deny.h` has (line 4), or `git add -f`; `helper.h` is tracked even though the rule matches it. Check that the PR actually contains the header.
- Crash window: binaries are installed (`bpf_client.go:235`) before the new objects are loaded (`bpf_client.go:275`). If the agent exits in between, the next start sees equal files and recovers the old pinned state (outcome unverified; raised on [#610](https://github.com/aws/aws-network-policy-agent/pull/610#discussion_r3677714530)).

<a id="p-marker"></a>
### [advisory] P3. One-time host migration with a marker file

Blocking only if: a failed step can still write the marker, so the migration is never retried.

`pkg/ebpf/legacy_pin_migration.go` is the pattern:

- Marker `/var/run/aws-node/.npa_format_v2` (`:21`). Present means no-op (`:39-43`).
- A missing input returns nil without writing the marker, so it retries on the next start (`:45-48`).
- Any failed step returns an error and skips the marker (`:92-94`). The marker is written only on full success (`:96-103`).
- Directories and marker path are parameters (`migrateLegacyPinsFromCNIState(progsDir, mapsDir, ipamPath, markerPath)`, `:38`), so tests use `t.TempDir()` (`legacy_pin_migration_test.go:30-220`).
- Called first in `recoverBPFState`; errors are not fatal (`bpf_client.go:488-495`).
- The old algorithm lives in one marked function: `utils.LegacyGetPodIdentifier` (`pkg/utils/utils.go:190-205`, with a removal TODO).

<a id="p-map"></a>
### [blocking] P4. Adding a per-pod map

Blocking when: a new per-pod map is missing from `NamespacedBPFMaps` (shared after restart, [C2](#c2)) or from `deleteBPFProgramAndMaps` (one set of pins leaks per deleted pod).

Define the map in C with `bpf_map_def_pvt` and `PIN_GLOBAL_NS` in each relevant tc program ([C14](#c14)). Add a name constant next to `TC_INGRESS_MAP` (`pkg/utils/utils.go:37-42`). Then add it in these places, or it is lost on restart or leaked on delete:

1. `NamespacedBPFMaps` (`pkg/utils/utils.go:52-62`).
2. `renamePinFamily` (`pkg/ebpf/legacy_pin_migration.go:119-126`), only if the map also existed in agents before the `_` separator change.
3. `deleteBPFProgramAndMaps` (`pkg/ebpf/bpf_client.go:1026-1069`), with a pin path helper in `pkg/utils/utils.go:228-245`.
4. `recoverBPFState` map lookups (`bpf_client.go:544-611`), if the map has a userspace shadow map.

<a id="p-recovery"></a>
### [advisory] P5. Recovery order at startup

Blocking only if: a program loaded before the events load stays attached after the events load replaces `aws_conntrack_map` ([C3](#c3)).

`NewBpfClient`: compare the events binary and choose the ingress variant (`bpf_client.go:214-215`), compare the rest (`:223`), install (`:235`), `recoverBPFState` (`:245`), load events only if needed (`:260`), run the deferred ct-deny probe if one is pending (`:318`), start conntrack GC (`:344-348`). `main.go` then calls `ReAttachEbpfProbes()` before controllers and the RPC server start. Recovery errors are logged and counted, never fatal (`bpf_client.go:529-533`). A `RecoverGlobalMaps` error returns early (`:504-508`), so per-pod recovery and reattach collection are skipped for that start. Readiness checks cover global map pins and bpffs (`main.go:138-147`, `pkg/ebpf/healthcheck.go:29-66`). New pinned state should be recovered here, not in a parallel path.

A new load that runs before the events load (`bpf_client.go:260-275`) relocates against the previous agent's global maps, whose conntrack value layout changed in v1.4.3 ([C4](#c4)). Place validation or probe loads after the events load, or skip them when `eventsUpdateRequired` is set or a global map is missing. `chooseIngressBinary` is the precedent: it defers the ct-deny probe until after the events load when the events binary changed or the globals don't recover (`bpf_client.go:1103-1125`).

<a id="p-metrics"></a>
### [advisory] P6. Metrics labels

- SDK latency: `sdkAPILatency` (`awsnodeagent_aws_ebpf_sdk_latency_ms`, labels `api`, `error`; `bpf_client.go:85-91`). Pattern: `start := time.Now()` ... `duration := msSince(start)`; `sdkAPILatency.WithLabelValues("attachIngressBPFProbe", fmt.Sprint(err != nil)).Observe(duration)` (`bpf_client.go:840-843`).
- SDK errors: `sdkAPIErr` (`awsnodeagent_aws_ebpfsdk_error_count`, label `fn`; `bpf_client.go:93-99`). Values follow `<operation>[-<qualifier>]`, for example `LoadBpfFile-NoPinPath` (`bpf_client.go:1191`) and `LoadBpfFile-CtDenyProbe` (`:1151`).
- Process-wide SDK counters use `prometheus.NewCounterFunc` (`bpf_client.go:105-119`).
- Registration is guarded by a package bool (`bpf_client.go:132-140`) on controller-runtime's `metrics.Registry`.
- Prefixes are already inconsistent (`awsnodeagent_aws_ebpf_sdk_`, `awsnodeagent_aws_ebpfsdk_`, unprefixed `network_policy_drop_*` in `pkg/ebpf/events/events.go:46-60`). Prefer a new label value on an existing metric. A new metric should join an existing family, not add a prefix.
- `msSince` returns fractional milliseconds (`bpf_client.go:128-130`). Don't reintroduce integer `Duration` division ([#689](https://github.com/aws/aws-network-policy-agent/pull/689#discussion_r4277219690)).

<a id="p-logging"></a>
### [advisory] P7. Logging

- Each agent package that logs defines `func log() logger.Logger { return logger.Get() }` (`bpf_client.go:80-82`). Use it, not `fmt.Println` (CLI output in `pkg/clihelper` excepted).
- The flag default is `debug` (`pkg/config/controller_config.go:17`), so Debug lines are not free at scale.
- Policy verdict logs: DENY at Info, ACCEPT and EXPIRED/DELETED at Debug (`pkg/ebpf/events/events.go:238-246`).
- Flow log text differs by family (`events.go:241` vs `:270`). Anything that greps flow logs must match both `Verdict: DENY` and `Verdict DENY`.
- The logger is a zap `SugaredLogger` (`pkg/logger/zaplogger.go:27`). Its format methods follow `fmt.Sprintf` (zap `sugar.go:378`), so `%w` renders as `%!w(...)`. Use `%v`.

<a id="p-flags"></a>
### [advisory] P8. Flags and environment variables

- Agent flag: constant, default and field in `pkg/config/controller_config.go:11-61`, bound in `BindFlags` (`:63-85`), validated in `ValidControllerFlags` (`:88-94`), parsed in `main.go:197-208`.
- `NewBpfClient` takes ten positional parameters (`bpf_client.go:165-166`), several adjacent `bool`s. Check argument order when adding one. `NewMockBpfClient` bypasses the constructor (`bpf_client_mock.go:13-24`), so new fields need setting there too.
- A new flag is a one-way door. Managed add-on users can change agent settings only through the add-on configuration, and exposing a flag there has needed product approval (maintainer guidance given outside GitHub; no public source). Each flag also multiplies the configurations tested at major releases. Reviewer's question: can the change ship without a flag? If a test needs a different code path, use a test-only mechanism (for example a test binary or image under `test/`), not a product flag.
- For a behavior gated by kernel or capability ([P9](#p-gate)) with no flag, turning it off means rolling back the agent. That is the case for the ct-deny objects. Ask whether that is acceptable, and make the PR say so.
- Delivery: the VPC CNI chart sets agent flags (`amazon-vpc-cni-k8s` at `a149c83c`, `charts/aws-vpc-cni/templates/daemonset.yaml:152-162`, `nodeAgent.*` values). A new flag needs a chart change in that repo to be settable.
- The only env var is `MY_NODE_NAME` (`pkg/ebpf/events/events.go:211`), from the downward API (chart `daemonset.yaml:147-151`).
- `NetworkPolicyMode` and `MultiNICEnabled` come from ipamd over gRPC, not flags (`main.go:210-234`).

<a id="p-gate"></a>
### [advisory] P9. Feature gating by kernel or capability

Blocking only if: the gate can choose a different object per pod or after `NewBpfClient` returns, with no fallback when the chosen object fails to load.

The agent has one runtime kernel gate: the choice between the ct-deny and the regular ingress object, `chooseIngressBinary` (`pkg/ebpf/bpf_client.go:1103-1125`). It is the precedent for a new gate:

- It decides once, in `NewBpfClient`, after the events-binary compare (`:214`) and before the ingress/egress compare (`:222`), at `:215`, or after the events load when the probe is deferred (`:318-324`), and before any pod is reattached. So every pod on the node runs one variant. The choice is kept in `bpfClient.ingressBinary` and not changed after `NewBpfClient` returns (`:378-380`).
- It checks the kfuncs (`:1105`), then loads the object once under a throwaway prefix and removes what the load pinned (`ctDenyBinaryLoads`, `:1130-1156`). The kfunc check alone does not prove the verifier accepts the object.
- It logs the decision on every path (`:1106`, `1150`, `1154`). A probe failure also counts `sdkAPIErr{fn="LoadBpfFile-CtDenyProbe"}` (`:1151`). A kernel without the kfuncs shows only as a Warn log line.
- Tests: `TestChooseIngressBinary` mocks the kfunc check and the SDK (`pkg/ebpf/bpf_client_test.go:1795`). The integration spec reads which variant the agent chose from its log, and skips where the ct-deny object is not in use (`test/integration/ebpf/ct_deny_test.go:131`).

A new gate should do the same: decide once at init, log the decision, expose it in a log line or metric, and have a nightly-matrix test for both sides. Deciding once avoids a mix of program variants on one node. Test-side precedent for a kernel-version check: `test/integration/policy/verifier_budget_test.go:278-290` reads `node.Status.NodeInfo.KernelVersion`, records it with `AddReportEntry`, and `Skip`s with the reason.

CI can't cover both sides of a kernel gate by itself. Test clusters are AL2023 only (`scripts/eks-test-cluster.sh:39`, `amiFamily: AmazonLinux2023`), and the nightly workflow is "Nightly AL2023 Kernel Tests" (`.github/workflows/nightly-kernel-tests.yaml:1`). If every AL2023 kernel passes the gate, the other side has no integration coverage, and once all CI kernels pass, the ungated object is never loaded in CI. For the ct-deny gate this likely means the regular ingress object is loaded in integration runs only where the probe fails (inferred for CI; the kfuncs need kernel 6.0, per `pkg/ebpf/c/ct_deny.h:20`). On AL2023 kernel 6.1.188, x86_64 and aarch64, all three kfuncs are in the `nf_conntrack` module's BTF (`/sys/kernel/btf/nf_conntrack`), not in `vmlinux`, and the agent chose the ct-deny object. The AL2 5.10.245 node has none of them (checked on np-npa-repro, 2026-11-03). The AL2023 6.12 line was not checked (unverified). Cover the other side with a privileged test that loads each shipped object on the node under a throwaway prefix, or with a test-only override that forces the other path on one leg. A unit test with the gate mocked does not load the object.

<a id="p-mode"></a>
### [advisory] P10. Strict mode, default state, and locking

Blocking only if: code takes `podIdentifierLocks` while its caller holds it (a deadlock), or writes a pod state that no later CNI ADD or reconcile rewrites.

- Read the mode with `GetNetworkPolicyMode()` / `utils.IsStrictMode` (`bpf_client.go:714-716`, `pkg/utils/utils.go:74-102`).
- Network-policy pod state defaults to `DEFAULT_DENY` in strict mode (`pkg/rpc/rpc_handler.go:93-97`, `bpf_client.go:666-669`). Cluster-policy state is `DEFAULT_ALLOW` on CNI ADD (`rpc_handler.go:99`, `:169`) and `POLICIES_APPLIED` when CNP rules exist (`controllers/clusterpolicyendpoints_controller.go:305-318`). But `ReAttachEbpfProbes` writes the mode default, `DEFAULT_DENY` in strict, to the cluster-policy key too (`bpf_client.go:684`, `:706`).
- Per-pod state is guarded by `podIdentifierLocks` (`bpf_client.go:400-404`). It is not re-entrant: never take it in a function called with it held. Some such helpers end in `Locked`, but the attach, load and delete helpers (`attachIngressBPFProbe`, `loadBPFProgram`, `deleteBPFProbes`) also run under it without the suffix. Compute map entries before taking it.

<a id="p-tests"></a>
### [advisory] P11. Where tests go and which CI runs them

Unit tests: `make test` runs `go test ./pkg/... ./controllers/...` (`Makefile:87-89`). Mock the SDK with its gomock mocks (`pkg/ebpf/bpf_client_test.go:18-21`). Controllers use `MockBpfClient` (`pkg/ebpf/bpf_client_mock.go`). Split pure logic out so it runs without a kernel (`entryActiveFromRead`, `pkg/ebpf/conntrack/conntrack_client.go:19-28`). The PR unit job never compiles the C; only the `docker-build` job does, on pull requests (`.github/workflows/pr-tests.yaml`). Verifier rejections show only on a real kernel.

Integration suites live in `test/integration/<suite>/`, one ginkgo suite per directory, built by `make build-test-binaries` (`Makefile:354-358`, all but `soak`). Placement decides where a test runs:

| Suite | PR `/test cyclonus` (`scripts/run-cyclonus-tests.sh`) | Nightly kernel (`scripts/run-kernel-smoke-tests.sh`) |
|---|---|---|
| `policy` | yes (`:118`) | yes (`:37`) |
| `ebpf` | yes when `RUN_EBPF_TESTS=true`, the default (`:120-123`) | yes (`:39`) |
| `clusternetworkpolicy` | yes (`:125-127`) | no |
| `restart` | only if `RUN_RESTART_TESTS=true`; default false, no workflow sets it (`:129-131`) | no |
| `agentflags` | yes when `RUN_AGENT_FLAGS_TESTS=true`, the default, after `restart` and before `strict` (`run_agent_flags_suite`, added in #782) | yes, before `strict` (`run_agent_flags_suite`, added in #782) |
| `strict` | yes, last (`:133-139`) | yes, last (`:41-43`) |
| `leak`, `upgrade`, `soak/port-reuse` | not run by any script or workflow | no |

All legs run on IPv4 and IPv6. The nightly kernel workflow (`.github/workflows/nightly-kernel-tests.yaml`) runs daily on AL2023 kernel lines and runs `policy`, `ebpf`, `agentflags`, then `strict`. #704 added `ebpf` to it, and #782 added `agentflags`. A test in a suite the nightly script does not run needs `run-kernel-smoke-tests.sh` extended ([Theme 16](#themes)). The strict suite mutates aws-node, so it must stay last. Restart tests assume default allow, so they run before it ([#706](https://github.com/aws/aws-network-policy-agent/pull/706#issuecomment-6227325153)). Suites that change aws-node run late, in isolation, with a restore. The `agentflags` specs change the agent's args, so the suite runs after the suites that expect the stock agent and before `strict`. `run_agent_flags_suite` in `scripts/lib/tests.sh` (added in #782) saves the args first and restores them after the suite, or from an `EXIT` trap if the script stops mid-suite. Without the restore, a run killed or timed out mid-suite would leave a flag on for `strict`. Shared helpers are in `test/framework` (`BuildBPFCheckPod`, `ParseLoadedEBPFData` in `test/framework/utils/bpf.go`).

**Specs that need an SDK change.** If a spec passes only with an SDK change that `go.mod` doesn't pin yet, it merges in the same PR as the SDK bump, or after it. The PR description names the SDK change and the release it needs. `/test cyclonus` builds the agent image from the PR head (`.github/workflows/pr-cyclonus-tests.yaml:97-109`), so the `go.mod` pin decides which SDK runs. The workflow runs only on an issue comment (`pr-cyclonus-tests.yaml:3-5`). The `ebpf` suite runs by default in that job (`scripts/run-cyclonus-tests.sh:42`, `:120-123`). A spec merged ahead of its SDK fix fails wherever its suite runs: the nightly kernel run fails it on both families (see the example below). The same `ebpf` suite runs in `/test cyclonus`, so it is expected to fail there too (inferred: no `/test cyclonus` has run on a PR head that includes such a spec).

Example: [#715](https://github.com/aws/aws-network-policy-agent/pull/715) (merged 2026-11-02 as `0c49457`, after 4bf96cf; change commit `5558fd6`) added `test/integration/ebpf/attach_rollback_test.go`. Its PR description reports that the first spec (`:74-89` at `0c49457`) fails with v1.0.19, because one `cp_egress_map` pin is left (pin check at `:220-226`), and passes with [SDK #179](https://github.com/aws/aws-ebpf-sdk-go/pull/179). The pass with SDK #179 is the author's report, not re-run here. The description said the PR should merge after the SDK bump. It merged while `go.mod` still pins v1.0.19, and the first spec fails on main: the nightly kernel run on `c50d4bb` ([run 41594235805](https://github.com/aws/aws-network-policy-agent/actions/runs/41594235805), 2026-11-03) failed it on all six legs (kernels 6.1, 6.12 and 6.18, IPv4 and IPv6) with one `pinfail@ebpf-security-test_cp_egress_map` pin left, and passed the second spec (`:91`). The previous nightly, before the merge, passed. No `/test cyclonus` has run since the merge. SDK #179 (`62628d3`) is released in v1.0.20 (2026-11-03). NPA main still pins v1.0.19 (`go.mod:8`).

Some CI text says the ebpf suite skips IPv6 (`pr-cyclonus-tests.yaml:192`, `run-cyclonus-tests.sh:10`, `:121`). The suite has no family-wide skip: `conntrack_poisoning_test.go:26-28` states it runs on both. The only `Skip`s in the suite are an IPv6-only spec skipping IPv4 (`hop_by_hop_icmpv6_test.go:41`) and the ct-deny spec skipping nodes that don't run the ct-deny object (`ct_deny_test.go:131`). Check which specs ran from the suite code and the run's report, not from the summary label.

Tests that read the node's conntrack table should look the tuple up, not scan it. `/proc/net/nf_conntrack` is produced one buffer per `read()` call, and each call restarts the walk at bucket 0 and skips forward by the count of hash nodes already returned, with no lock held between calls (Linux v6.1 `net/netfilter/nf_conntrack_standalone.c:141-161`, `fs/seq_file.c:225`, `:254-279`; same in v5.10 and v6.12). The table holds both directions of every connection in every netns, so a deletion ahead of the cursor in any pod shifts the walk and the next call skips an entry. This was measured (not re-run here, unverified): on a node whose table churned up to 1,841 entries, 8 of 300 reads missed a long-lived entry; on a quiet table, none did. Look the tuple up over netlink with `conntrack -G` instead. The EKS AL2023 AMI installs the `conntrack` package (`amazon-eks-ami` `templates/al2023/provisioners/install-worker.sh:56`). Run it from a privileged check pod with the host root at `/host`, such as `BuildBPFCheckPod` (`test/framework/utils/bpf.go:15-35`): `chroot /host conntrack -G -p tcp -s <src> -d <dst> --sport <sport> --dport <dport>`, as `test/integration/ebpf/ct_deny_test.go:295` does.

Test pods also need distinct pod identifiers when the test expects separate programs or maps ([P12](#p-podid)).

<a id="p-podid"></a>
### [advisory] P12. Pod identifiers

Blocking only if: pods that commonly share an identifier, such as replicas of one Deployment, need different values of the new state. A collision that needs an unusual pod name is advisory.

`GetPodIdentifier` (`pkg/utils/utils.go:177-188`) turns a pod name and namespace into the key for a pod's BPF state:

- It drops the name's last `-` segment: `client-7d9f-abcde` and `client-7d9f-xyz12` both give `client-7d9f@<ns>`. A name without `-` is kept whole.
- It replaces `.` with `_` (`:178-181`), which collides with the SDK's split of pin names at the first `_` ([C1](#c1)).

So pods that differ only in the last segment, such as Deployment replicas, share one identifier. On a node they share one set of BPF programs and policy maps: `attachIngressBPFProbe` reuses the program loaded for the identifier (`pkg/ebpf/bpf_client.go:888-905`, same for egress), and the pin paths are derived from the identifier (`utils.go:219-245`). Locks and per-pod state are keyed by it too ([P10](#p-mode)).

For tests, give pods that need separate programs or maps names that differ before the last `-`, for example `client-a-0` and `client-b-0`, and use no `.` in names. For code, ask whether a change keys new state by pod identifier or by pod (`GetPodNamespacedName`, `utils.go:165-171`), and whether two pods that share an identifier can need different values.

<a id="p-cache"></a>
### [blocking] P13. Cached reads in the reconcilers

Blocking when: code writes through any value reached from a cached object, including slice elements and the `Protocol` / `Port` / `EndPort` pointers.

The PolicyEndpoint and ClusterPolicyEndpoint reconcilers read from the informer cache with `client.UnsafeDisableDeepCopy` (`controllers/policyendpoints_controller.go:124-125`, `:165`, `:587`, `:837`; `controllers/clusterpolicyendpoints_controller.go:80-81`, `:120`, `:357`, `:605`). The returned objects are shared with the cache and must not be mutated. Rule derivation passes `slices.Clip` of `Except` and `Ports` (the CPE path has only `Ports`), so an append reallocates, but the existing elements and the `Protocol` / `Port` / `EndPort` pointers inside each port still belong to the cache (comments at `policyendpoints_controller.go:594-598`, `clusterpolicyendpoints_controller.go:364-368`). `TestFirewallRuleDerivation_LeavesCachedObjectsUnchanged` (`controllers/deepcopy_bench_test.go:261`) checks that deriving rules leaves cached objects unchanged.

For a change in these paths, check that no code writes through a value reached from a cached object, including in `pkg/fwruleprocessor`. A new read path should either keep the option and treat the result as read-only, or drop it. Extend that test when rule processing changes.

<a id="p-requeue"></a>
### [blocking] P14. Reconcile failures are returned

Blocking when: a failure that leaves rules, pod state or an attach wrong is logged and `Reconcile` returns nil. An expected, benign skip error that now requeues is advisory.

**Rule.** If a failure leaves datapath state wrong (rules not written, pod state missing, a direction not attached), return it from `Reconcile` so controller-runtime requeues the request with backoff. In a loop, record the failure, continue with the other identifiers or pods, and return the `errors.Join` of the failures. Don't log and return nil, and don't rely on the resync. Wrap an error that no retry can fix in `reconcile.TerminalError`.

**Why.** controller-runtime requeues a request only if `Reconcile` returns an error, or a result with `Requeue` / `RequeueAfter`. If it returns nil, the next attempt waits for the next change to that PolicyEndpoint or for the cache resync. NPA sets no sync period: `BuildRuntimeOptions` sets only the scheme, metrics and health probe address. The `SyncPeriod` field in `RuntimeConfig` is never read. So controller-runtime's default of 10 hours applies. Until then, the pod enforces stale rules, or drops all traffic in a direction that has no pod state ([C21](#c21)). The main signals are an agent log line and, for SDK call failures, the `sdkAPIErr` counter; nothing requeues. A `TerminalError` is counted but not requeued.

**Precedent (NPA 4bf96cf).** Main follows this rule since [#726](https://github.com/aws/aws-network-policy-agent/pull/726) (commit `c93b854`). Follow main's pattern:

- Both `Reconcile` methods return the error from `reconcile`: `controllers/policyendpoints_controller.go:154-160`, `controllers/clusterpolicyendpoints_controller.go:108-115`.
- `reconcilePolicyEndpoint` records derive and configure failures per identifier, then returns the join: `policyendpoints_controller.go:333-337`, `354-360`, `372`.
- `cleanUpPolicyEndpoint` does the same: `:252`, `:261`. The CPE reconciler: `clusterpolicyendpoints_controller.go:222-237`.
- `attachProbesForIdentifier` records each pod's attach failure and continues: `controllers/shared.go:54-77`.

**Cites.** NPA 4bf96cf: `pkg/config/runtime_config.go:35` (`SyncPeriod`, no reader in `main.go`, `pkg/` or `controllers/`), `runtime_config.go:66-72` (`BuildRuntimeOptions`). controller-runtime v0.25.2: `pkg/internal/controller/controller.go:485-497` (rate-limited requeue on error; `TerminalError` is only counted), `:554-556` (`AddRateLimited`), `pkg/cache/cache.go:45` (`defaultSyncPeriod = 10 * time.Hour`), `:457`.

**Check.** In a controller diff, follow every `log().Errorf` on a programming path to the `Reconcile` return value. Reject a new `return nil` after a failure that leaves state wrong. For a new loop, does one failure stop the remaining identifiers? It shouldn't. Does a test assert that the failure reaches `Reconcile`'s error?

<a id="p-scale"></a>
### [advisory] P15. Periodic work scales with the agent's own state

**Rule.** A periodic task should cost in proportion to what the agent owns, such as its conntrack map entries, pods or policies, not to a node-wide kernel table. If a change adds or touches such a task, ask what its memory and CPU scale with, and for the agent's memory at a large table. For conntrack, that means a few hundred thousand kernel entries.

**Why.** `CleanupConntrackMap` runs every half period and alternates two phases. One reads the agent's `aws_conntrack_map` into `localConntrackV4Cache`. The next dumps the kernel table. So the whole kernel table is read once per `--conntrack-cache-cleanup-period` (default 300 s). `netlink.ConntrackTableList` holds the raw dump and the parsed `[]*ConntrackFlow` at once. NPA then builds `kernelConntrackV4Cache` with up to four keys per kernel flow, and only then looks up its own entries. Peak memory per cycle therefore follows the node's kernel table, which grows with busy services or a connection flood. The agent's own map is bounded by `--conntrack-cache-table-size`.

Measured in [#746](https://github.com/aws/aws-network-policy-agent/issues/746) on stock v1.4.3 with default flags. Agent RSS was about 48 MiB at about 270 kernel entries and 441 MiB at about 417,000, so roughly 1 KB per kernel entry. The spikes came at the 300 s cadence. (Per the issue's measurement, not re-run here.) The dump and map-building lines are unchanged from v1.4.3 to 4bf96cf (`git diff v1.4.3 4bf96cf`), so main should behave the same (inferred).

A dump that the kernel marks interrupted (`NLM_F_DUMP_INTR`) returns `ErrDumpInterrupted` along with partial results. NPA treats any error as a failure and skips that cycle. So on a busy table, GC may also skip cycles (inferred; when the kernel interrupts a dump is unverified).

**Cites.** NPA 4bf96cf:

- Schedule: `pkg/ebpf/bpf_client.go:342-347` (`wait.Forever(..., halfDuration)`), `pkg/config/controller_config.go:22` (`defaultConntrackCacheCleanupPeriod = 300`), `:23` (`defaultConntrackCacheTableSize = 512 * 1024`).
- Phases in `pkg/ebpf/conntrack/conntrack_client.go`: `:89-134` (hydrate), `:136-246` (kernel phase).
- Kernel phase: `:146` (dump), `:147-150` (any error returns), `:151-209` (four-key map), `:213-238` (lookup of own entries).
- The v6 path is the same: `:320`, `:326-391`.

netlink v1.3.1: `conntrack_linux.go:93-105` (whole dump parsed into one slice; partial results returned with `ErrDumpInterrupted`), `:211-213`, `nl/nl_linux.go:48-51`, `:610`, `:666`.

**Check.** For a new or changed periodic loop or per-event path, name what its cost scales with. If that is a kernel table (conntrack, links, routes, neighbors), can it look up only the agent's own entries, or filter while the dump streams? Ask for RSS or heap at rest and at a large table, before and after ([Theme 9](#themes)).

<a id="themes"></a>
## 6. Recurring review themes

Roughly ordered by how often maintainers raised them (approximate, hand-tagged counts). Themes that are general review hygiene are grouped in the last two rows; their questions are in [General review hygiene](#ck-general).

| # | Severity | Theme | Reviewer's question | Examples |
|---|---|---|---|---|
| 2 | blocking | v4/v6 parity | Is the change in both families (C, GC, CLI, tests), and was it run on IPv6? Blocking when: a C or conntrack GC change to what is allowed, denied or deleted lands in one family only. | [#584](https://github.com/aws/aws-network-policy-agent/pull/584#pullrequestreview-4348586222), [#682](https://github.com/aws/aws-network-policy-agent/pull/682#discussion_r4355500501) |
| 6 | advisory | Retries terminate | Is each failure returned so that it retries at all ([P14](#p-requeue))? Will each retried error resolve? Is it matched by type or sentinel, not text? Blocking only if: a failure that leaves datapath state wrong is not returned at all ([P14](#p-requeue)). | [#690](https://github.com/aws/aws-network-policy-agent/pull/690#discussion_r4305104606), [#627](https://github.com/aws/aws-network-policy-agent/pull/627#discussion_r4342500099), [#732](https://github.com/aws/aws-network-policy-agent/issues/732) |
| 12 | blocking | SDK naming assumptions | Does a new map name or pod identifier fit the SDK's `_` parsing, stay unique across valid pod names, and is the map registered? Blocking when: a prefix contains `_` for ordinary names ([C1](#c1)), or a per-pod map is not in `NamespacedBPFMaps` ([C2](#c2)). | [#704](https://github.com/aws/aws-network-policy-agent/pull/704#discussion_r4365251642), [#576](https://github.com/aws/aws-network-policy-agent/pull/576#discussion_r3337784351) |
| 14 | blocking | C, Go and pinned layouts agree | Do C struct, Go mirror, copy sites and pinned map match? Is no old encoded value reused with a new meaning? Blocking when: a Go mirror's size or padding differs from C ([C12](#c12)), or n-1 and this version read a surviving conntrack value differently. | [#584](https://github.com/aws/aws-network-policy-agent/pull/584#discussion_r3314518432), [#682](https://github.com/aws/aws-network-policy-agent/pull/682#discussion_r4355507085) |
| 16 | advisory | Kernel matrix | Are new eBPF tests in the nightly kernel workflow? Which kernels and OSes were tested? | [#704](https://github.com/aws/aws-network-policy-agent/pull/704#discussion_r4338695694), [#558](https://github.com/aws/aws-network-policy-agent/pull/558#issuecomment-4556598415) |
| 17 | advisory | Strict mode and default state | Is it correct in strict and standard mode, for NP and CNP state? Blocking only if: in one mode a pod ends with a state that allows what policy denies, or denies what it allows, and no later CNI ADD or reconcile rewrites it. | [#682](https://github.com/aws/aws-network-policy-agent/pull/682#discussion_r4189768987), [#706](https://github.com/aws/aws-network-policy-agent/pull/706#issuecomment-6227325153) |
| 18 | advisory | Multi-NIC | Is `INTERFACE_COUNT_UNKNOWN` a warning in reconcilers and a failure in CNI ADD? Blocking only if: CNI ADD proceeds without the interface count, so the pod starts with some interfaces unattached (inferred). A reconciler that requeues on an unknown count is advisory. | [#690](https://github.com/aws/aws-network-policy-agent/pull/690#discussion_r4305204640) |
| 19 | blocking | Partial failure leaves a programmable datapath | After a failure between any two attach or map steps, is every attached filter's program pinned, in the context, and given pod state? ([C21](#c21)) Blocking when: a failure path unpins or unloads a program that an attached filter still runs ([C21](#c21)). | [#744](https://github.com/aws/aws-network-policy-agent/issues/744), [#732](https://github.com/aws/aws-network-policy-agent/issues/732) |
| 21 | blocking | Fail closed on a lookup miss | When a map entry exempts a packet from evaluation or from flow recording, what happens when the lookup misses? Is that path safe with policy allowing everything else? Blocking when: a miss lets a packet record a flow, or pass, that policy would deny. | [#782](https://github.com/aws/aws-network-policy-agent/pull/782#discussion_r4546966912) |
| 20 | advisory | Cost scales with agent state | Does periodic work scale with what the agent owns, not with node-wide kernel tables? Are numbers at a large table attached? ([P15](#p-scale)) | [#746](https://github.com/aws/aws-network-policy-agent/issues/746) |
| 4, 7, 11 | advisory | Upgrade and downgrade (4); recovery after restart (7); syscall memory safety (11) | See [General review hygiene](#ck-general). Blocking only if: a node stays broken after an upgrade or rollback completes ([C11](#c11)), or a buffer is shorter than its map's sizes ([C12](#c12)). | 4: [#576](https://github.com/aws/aws-network-policy-agent/pull/576#issuecomment-4501362883), [#576](https://github.com/aws/aws-network-policy-agent/pull/576#discussion_r3359126004). 7: [#576](https://github.com/aws/aws-network-policy-agent/pull/576#discussion_r3337784352), [#566](https://github.com/aws/aws-network-policy-agent/pull/566#pullrequestreview-4232618343). 11: [#610](https://github.com/aws/aws-network-policy-agent/pull/610#discussion_r3634710968), [SDK #176](https://github.com/aws/aws-ebpf-sdk-go/pull/176#discussion_r4343396756) |
| 1, 3, 5, 8, 9, 10, 13, 15 | advisory | Tests give real signal (1); log volume (3); reuse existing helpers (5); comments and PR description (8); performance numbers (9); metrics measure the right thing (10); right layer (13); real concurrency (15) | See [General review hygiene](#ck-general). | 1: [#614](https://github.com/aws/aws-network-policy-agent/pull/614#discussion_r3598831431), [SDK #176](https://github.com/aws/aws-ebpf-sdk-go/pull/176#discussion_r4343380166). 3: [#623](https://github.com/aws/aws-network-policy-agent/pull/623#discussion_r3772059282), [#627](https://github.com/aws/aws-network-policy-agent/pull/627#discussion_r4343154655). 5: [#584](https://github.com/aws/aws-network-policy-agent/pull/584#discussion_r3320444420), [#610](https://github.com/aws/aws-network-policy-agent/pull/610#discussion_r3679133941). 8: [#690](https://github.com/aws/aws-network-policy-agent/pull/690#issuecomment-6243838959), [#605](https://github.com/aws/aws-network-policy-agent/pull/605#issuecomment-5260978219). 9: [#623](https://github.com/aws/aws-network-policy-agent/pull/623#pullrequestreview-4777192709), [#627](https://github.com/aws/aws-network-policy-agent/pull/627#discussion_r4343183533). 10: [#689](https://github.com/aws/aws-network-policy-agent/pull/689#discussion_r4277202698), [#690](https://github.com/aws/aws-network-policy-agent/pull/690#discussion_r4305142623). 13: [#690](https://github.com/aws/aws-network-policy-agent/pull/690#discussion_r4305115662), [#627](https://github.com/aws/aws-network-policy-agent/pull/627#discussion_r4182178666), [#715](https://github.com/aws/aws-network-policy-agent/pull/715) |
