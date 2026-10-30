# Review guide for aws-network-policy-agent

## 1. Purpose and how to use it

This guide lists the problems maintainers keep finding in review, so authors and reviewers can find them first. It covers four areas: the implicit contracts of `aws-ebpf-sdk-go`, v4/v6 parity, existing precedents to reuse, and recurring review themes.

Run it against a diff. For each changed area, look up the matching checks:

| If the diff touches | Read |
|---|---|
| `pkg/ebpf/bpf_client.go`, `pkg/ebpf/conntrack/`, `pkg/ebpf/events/`, `pkg/clihelper/`, any `goelf.*` / `tc.*` / `goebpfmaps.*` call | [Quick checklist: SDK boundary](#ck-sdk), [section 3](#sdk) |
| `pkg/ebpf/c/*` | [BPF programs](#ck-bpf), [v4/v6 parity](#parity), [P2](#p-change) |
| A file with a `v4`/`v6` or `IPv6` twin, or a header with `_v4`/`_v6` functions | [v4/v6 parity](#parity) |
| `checkAndUpdateBPFBinaries`, `recoverBPFState`, `ReAttachEbpfProbes`, `NewBpfClient`, `legacy_pin_migration.go`, pinned maps | [Upgrade, downgrade, recovery](#ck-upgrade), [precedents](#precedents) |
| `pkg/utils/cp/`, `Makefile`, `Dockerfile`, `.gitignore` | [Host files and binaries](#ck-host) |
| Metrics, log lines, flags | [Metrics, logging and flags](#ck-obs), [P6](#p-metrics), [P8](#p-flags) |
| `controllers/`, `GetPodIdentifier` | [Controllers and pod identifiers](#ck-ctrl), [P12](#p-podid), [P13](#p-cache) |
| `test/`, `scripts/`, `.github/workflows/` | [Tests and CI](#ck-tests), [P11](#p-tests), [P12](#p-podid) |

To compare a change with its merge base without writing to the repository, extract both trees: `git archive <rev> pkg/ebpf/c | tar -x -C <dir>`. See [Running the diff helper](#parity-diff).

**Citations.** Every citation is `path:line` at a named commit. If a line has moved, find it by the quoted symbol.

- NPA: `aws/aws-network-policy-agent` at `1703063`.
- SDK: `aws/aws-ebpf-sdk-go` v1.0.19 at `9127cb7`, unless marked v1.0.17 (`24af48f`, the version NPA pins).
- Libraries, as pinned in NPA `go.mod`: `vishvananda/netlink` v1.3.1, `go.uber.org/zap` v1.28.0.
- VPC CNI chart: `aws/amazon-vpc-cni-k8s` at `a149c83c`.
- EKS AMI: `awslabs/amazon-eks-ami` at `6832b07b`.

**SDK version.** NPA at `1703063` pins SDK v1.0.17 (`go.mod:8`). Between v1.0.17 and v1.0.19 the SDK changed in two ways that matter here:

- kfunc support (`pkg/btf`, `pkg/internal/btf`, kfunc relocation in `elfparser`) is new in v1.0.18. v1.0.17 has none.
- `CleanupQdiscs` and `GetAllAttachedProgIds` switched from host-hook directions to pod directions in v1.0.19, with no signature change. See [C11](#c11).

All other SDK behavior cited here is the same in v1.0.17 and v1.0.19. Line numbers differ between versions.

Items marked "(unverified)" or "(inferred)" rest on reasoning, or on kernel or Kubernetes behavior that was not traced in source. Treat them as questions, not facts.

## 2. Quick checklist

<a id="ck-sdk"></a>
**SDK boundary**

- Can any `LoadBpfFile*` prefix contain `_`, including through `GetPodIdentifier`? [C1](#c1)
- Is every new per-pod map in `NamespacedBPFMaps`? [C2](#c2)
- Is any global map name defined by two ELFs? What reloads the programs that use a reloaded global map? [C3](#c3)
- Does new startup or CLI code recover globals first, and does it handle partial recovery? [C4](#c4)
- Is each field read from `BpfData` populated by the API that produced it? [C5](#c5)
- For each `UnPinMap`, `UnPinProg` or close: which other copies hold that FD? [C6](#c6)
- Which lock keeps this load away from other loads with the same prefix? [C7](#c7)
- What happens if this load fails half way under a live prefix? [C8](#c8)
- Is `GetAllAttachedProgIds`'s error checked before `CleanupQdiscs`? Does anything else put tc filters on `eni*`/`vlan*`? [C9](#c9)
- Is the detach-then-attach gap acceptable? Is a new error-string match on TC errors avoidable? [C10](#c10)
- Which SDK version does `go.mod` pin, and does the caller assume pod or host direction? [C11](#c11)
- Is `errors.Is(err, unix.ENOENT)` used only after a next-key API? Is `CreateMapEntry` meant to keep an existing value? [C13](#c13)
- Is `CheckKfuncs` called once at startup, and what happens if a kfunc load fails later? Where does the failure reason show? [C17](#c17), [C19](#c19)
- Is there exactly one `InitRingBuffer` call, and does its consumer avoid blocking work? [C18](#c18)
- Which log line or metric shows this new failure mode in production? [C19](#c19)
- Does the change hard-code `/sys/fs/bpf` paths or path depth? [C20](#c20)

<a id="ck-bpf"></a>
**BPF programs (C)**

- Do Go key and value sizes equal the C `key_size` / `value_size`? [C12](#c12)
- Is `struct bpf_map_def_pvt` unchanged (7 x `__u32`, pinning 6th), and is every `.pinning` `PIN_GLOBAL_NS`? [C14](#c14)
- Does any code read a kernel-internal struct field, a global variable, or a `.maps` map? [C15](#c15)
- Is every program section in the SDK's set, and do function names match `TC_*_PROG`? [C16](#c16)
- Are helpers that call kfuncs `__always_inline`? [C16](#c16)
- Is the change made in all four tc programs, and in both events files if it touches a shared struct? [Parity](#parity)
- Does the change alter the bytes of objects whose behavior it doesn't change, for example through an `#include` or a comment? [P2](#p-change)
- Is an existing conntrack value encoding reused with a new meaning? [Theme 14](#themes)

<a id="ck-parity"></a>
**v4/v6 parity**

- Is the same change in the v4 and v6 C programs, conntrack GC, event decoding, CLI and tests? [Parity table](#parity-table)
- Does `hack/v4v6-diff.py` show new hunks on the change compared with its merge base? [Diff helper](#parity-diff)
- Does a shared header define `_v4`/`_v6` function pairs? Run the helper's `--funcs` mode on it. [Diff helper](#parity-diff)
- Does a new family switch go through the existing selection code instead of adding another copy? [Parity table](#parity-table)
- Was the change run on an IPv6 cluster? [P11](#p-tests)

<a id="ck-upgrade"></a>
**Upgrade, downgrade, recovery**

- What happens to pinned programs, pinned maps, tc filters and conntrack entries on upgrade, on rollback to n-1, and on an agent crash between any two startup steps? [P2](#p-change), [P5](#p-recovery)
- Does a changed object get reloaded by the byte compare? If the logic is unchanged but a reload is needed, is `NPA_FILE_VERSION` bumped in all four tc programs? [P2](#p-change)
- Does the change alter only one direction's objects relative to n-1? If n-1, or this agent, runs SDK v1.0.17 or v1.0.18, the cleanup removes the other direction's filters. [C11](#c11), [P2](#p-change)
- Does any startup load happen before the events-binary decision, and does it depend on the conntrack value layout? [C4](#c4), [P5](#p-recovery)
- Does the events object change? If so, every pod is reattached with default state and the conntrack map is recreated. Is that intended? [P2](#p-change)
- Does a one-time host migration follow the marker-file pattern? [P3](#p-marker)
- Is new pinned state recovered through `recoverBPFState`, not a parallel path? [P4](#p-map), [P5](#p-recovery)
- Is any conntrack value byte reused with a new meaning across versions? [Theme 14](#themes)

<a id="ck-host"></a>
**Host files and binaries**

- Is a new object in `bpfBinaries`, `Makefile` `build-bpf`, `Dockerfile` `COPY`, and the name checks in `checkAndUpdateBPFBinaries`? [P2](#p-change)
- Does a family or feature variant install under one stable host name? [P1](#p-hostname)
- Does a new header in `pkg/ebpf/c/` have a `.gitignore` exception? `.gitignore` ignores `*.h`. [P2](#p-change)
- Do host-side tests call `/opt/cni/bin/aws-eks-na-cli` on both families? [P1](#p-hostname)

<a id="ck-obs"></a>
**Metrics, logging and flags**

- Does the change reuse `sdkAPILatency` / `sdkAPIErr` with a new, greppable label value? [P6](#p-metrics)
- Does a timer cover only the operation it names, with sub-millisecond precision? [P6](#p-metrics)
- Does a new log line fire per entry, per pod or per retry at the default debug level? Is the same error logged at several layers? [P7](#p-logging), [Theme 3](#themes)
- Does anything that parses flow logs handle both the v4 and v6 formats? [P7](#p-logging)
- Does the change add an agent flag? Could it ship without one? If a test needs another code path, can a test-only mechanism provide it? [P8](#p-flags)
- How does an operator turn a gated behavior off? If the answer is "roll back the agent", does the PR say so? [P8](#p-flags), [P9](#p-gate)
- Is a new flag also added to the VPC CNI chart? [P8](#p-flags)

<a id="ck-tests"></a>
**Tests and CI**

- Does each new test fail on main, pass with the change, call production code, and avoid sleeps and absolute counts? [Theme 1](#themes)
- Is the test in a suite that CI actually runs, including the nightly kernel workflow for eBPF changes? [P11](#p-tests)
- Is there a privileged test that loads the built ELF, for C changes that only fail at load time? [C16](#c16)
- Does the test work on IPv4 and IPv6, and in strict and standard mode? [P10](#p-mode), [P11](#p-tests)
- Is a feature gate tested on both sides of the gate, given that CI nodes are AL2023 only? [P9](#p-gate)
- Do test pods that need separate programs have names that differ before the last `-`, and no `.`? [P12](#p-podid)
- Does a test that reads the node's conntrack table look the tuple up with `conntrack -G`, not by scanning `/proc/net/nf_conntrack`? [P11](#p-tests)
- Does a claim about which suites run on which family come from the suite's code, not a CI comment or label? [P11](#p-tests)

<a id="ck-ctrl"></a>
**Controllers and pod identifiers**

- Does new code write to an object read with `client.UnsafeDisableDeepCopy`, including slice elements and pointers inside it? [P13](#p-cache)
- Can two pods that should be enforced separately end up with one pod identifier? [P12](#p-podid)

<a id="ck-pr"></a>
**PR hygiene**

- Do code comments describe current behavior and why, without change history? [Theme 8](#themes)
- Does the PR description match the final code and include test results (families, OS, kernels, upgrade/downgrade)? [Theme 8](#themes)
- For hot-path or scale changes, are before/after numbers attached? [Theme 9](#themes)
- Does the change belong in the SDK or the controller instead, and does it need an SDK release first? [Theme 13](#themes)

<a id="sdk"></a>
## 3. SDK contracts

These are rules a caller must follow that the SDK neither enforces nor documents. "Silent" means no error reaches the caller and nothing is logged at error level in the agent log.

<a id="c1"></a>
### C1. Pin prefixes must not contain `_`

**Rule.** Every `CustomPinPath` / prefix passed to `LoadBpfFile*` must be non-empty and free of `_`. The part of a pin name after its first `_` must equal the ELF map or function name.

**Why.** The SDK splits pin names at the first `_` to find the namespace. With prefix `A_B`, the map pin `A_B_ingress_map` parses as namespace `A`, name `B_ingress_map`. That name is not namespaced, so the map is treated as global. At load time it is cached under its bare ELF name, so the SDK cache now maps `ingress_map` to this pod's FD (`elf.go:273-276`). At the next restart, `RecoverAllBpfProgramsAndMaps` cannot find the program's namespace and aborts the walk with "failed to get err", unless some other per-pod map pin happens to start with `A_`. When it aborts, no pod on the node is recovered. The load itself is silent.

**Cites.** SDK 9127cb7: `pkg/elfparser/elf.go:1145` (`strings.Cut(lastSegment, "_")`), `elf.go:242-246` and `1047-1051` (pin = prefix + `_` + name), `elf.go:1311` (prog split), `elf.go:1343-1347` (abort). NPA 1703063: `pkg/utils/utils.go:173-188` (`GetPodIdentifier` joins with `@` for this reason).

The code doesn't enforce this today: `GetPodIdentifier` replaces `.` in the pod name with `_` (`utils.go:178-181`). See [P12](#p-podid) for the rest of the identifier rules.

**Check.** `grep -n 'LoadBpfFile' -r pkg`. Every prefix must be a constant without `_`. A `GetPodIdentifier` result is not safe today (dotted pod names produce `_`). A unit test can assert `GetMapNameFromBPFPinPath(MAP_BPF_FS + prefix + "_ingress_map")` returns `("ingress_map", prefix)` for each prefix shape. The method is not on `BpfSDKClient`, so call it via `goelf.New(cfg).(interface{ GetMapNameFromBPFPinPath(string) (string, string) })`.

<a id="c2"></a>
### C2. Every per-pod map must be in `NamespacedBPFMaps`

**Rule.** Every `SEC("maps")` symbol in a per-pod ELF must be listed in `Config.NamespacedMaps`.

**Why.** An unlisted map is global to the SDK. `RecoverGlobalMaps` caches every global pin under its bare name, last writer wins. `RecoverAllBpfProgramsAndMaps` checks that cache before the pod's own FD. After a restart, every pod except the last one walked has `Maps["newmap"]` holding another pod's FD with its own map ID. Writes go to the wrong pod's map. Silent, and only after a restart (fresh loads use local maps first).

**Cites.** SDK 9127cb7: `elf.go:1157-1160` (`IsMapGlobal`), `elf.go:1188`, `1204` (cache set), `elf.go:1352-1364` (cache before local). NPA 1703063: `pkg/utils/utils.go:52-62`, passed at `pkg/ebpf/bpf_client.go:183` and `pkg/clihelper/show.go:41`.

**Check.** `grep -n 'SEC("maps")' pkg/ebpf/c/tc.*.bpf.c` and compare with `NamespacedBPFMaps`. See [P4](#p-map) for the other places a new map must be added.

<a id="c3"></a>
### C3. Global map names are one process-wide namespace

**Rule.** A global map name must be defined by exactly one ELF in the process. When that ELF is reloaded, every program that uses its maps must be reloaded too.

**Why.** The SDK has one package-level FD cache keyed by bare map name, shared by every `elfparser.New` client, never cleared. Relocation writes the FD into the instruction at load time. A second ELF that defines `aws_conntrack_map` overwrites the cache, so later loads bind to the new map while loaded programs keep the old one. Reloading the events ELF unlinks and re-pins the conntrack map, so old TC programs write a map that userspace no longer reads. Silent in both cases.

**Cites.** SDK 9127cb7: `pkg/cache/cache.go:23,58-71`, `elf.go:56`, `elf.go:731-740`, `pkg/maps/loader.go:231-261`. NPA 1703063: events ELF loaded with prefix `global` (`pkg/ebpf/bpf_client.go:236-245`). The byte-compare path forces both TC directions to reload (`bpf_client.go:397-403`). The missing-global-map path (`:230`, also reached after a `RecoverGlobalMaps` error at `:444`) reloads the events ELF without reloading TC programs, so it does not meet this contract until each pod is re-attached.

**Check.** `grep -n 'SEC("maps")' -A1 pkg/ebpf/c/*.c`. Ask: "If this ELF is reloaded, what reloads everything that references its maps?"

<a id="c4"></a>
### C4. Recovery: order, all-or-nothing, and foreign pins

**Rule.**

- In each process, run `RecoverGlobalMaps` (or load the ELF that defines the globals) before `RecoverAllBpfProgramsAndMaps` and before loading any ELF that uses globals it doesn't define.
- Only SDK-created pins may exist under `/sys/fs/bpf/globals/aws/maps/` and `/programs/`. Every program pin name must contain `_`.
- A `RecoverGlobalMaps` error can mean "no maps directory yet". Don't call it in a loop.
- A load at startup that uses globals the ELF doesn't define relocates against whatever is pinned. Before the events-binary decision, that is the previous agent's maps.

**Why.** Global FDs reach relocation and recovery only through the cache. Any per-entry error aborts the `filepath.Walk` and the function returns no results, so one bad pin loses recovery for the whole node. A program pin name without `_` panics with an index out of range. The agent exits and (inferred) restarts into the same panic on every start. `RecoverGlobalMaps` fails when the maps directory is missing (for example after a reboot, unverified) and opens one new FD per global pin on each call without closing the old ones.

**Cites.** SDK 9127cb7: `elf.go:731-736`, `elf.go:1171-1222`, `1259-1296`, `1300-1392` (walks), `elf.go:1311-1312`, `1470-1471` (`podIdentifier[1]`), `elf.go:1197-1204`, `1277-1279`, `1352-1361` (globals only from the cache). NPA 1703063: `pkg/ebpf/bpf_client.go:439-470` (order; errors logged, never fatal). A `RecoverGlobalMaps` error returns early (`:444`), so per-pod recovery is skipped too.

The events-binary decision is the compare at `bpf_client.go:196`, and the events load follows at `:230-245`. A startup load placed before the events load binds to the `aws_conntrack_map` the previous agent pinned. Its layout depends on that agent's version: `struct conntrack_value` is `{ __u8 val; }` (1 byte) up to v1.4.2 and `{ __u64 val; __u64 last_seen; }` (16 bytes) from v1.4.3 (`pkg/ebpf/c/v4events.bpf.c:41` at both tags). A validation or probe load whose program reads the 16-byte value then fails, or passes, depending on the version being upgraded from (inferred from the verifier's map-value bounds check, not reproduced).

**Check.** In any new startup or CLI path, trace the first SDK call. For a load before `:230`, ask what it binds to when the events binary changes, and whether it can wait until after the events load. Any code that pins under `/sys/fs/bpf/globals/aws/` outside `LoadBpfFile*` (test helpers, migrations) must keep the `<prefix>_<name>` shape. Count `RecoverGlobalMaps` calls per process.

<a id="c5"></a>
### C5. `BpfData` contents depend on the API that produced it

**Rule.** Don't assume `Maps`, `MapFD`, `ProgFD` or `ProgID` mean the same thing across APIs.

| API | `Maps` | Program fields |
|---|---|---|
| `LoadBpfFile*` | Only maps this ELF defines **and** the program references. Globals from the cache are absent | `ProgFD`, `ProgID` set |
| `RecoverAllBpfProgramsAndMaps` | All associated maps, including globals (cache FD) | `ProgFD`, `PinPath`; `ProgID == 0` |
| `GetAllBpfProgramsAndMaps` | Every `MapFD` is 0 | `ProgID` set; no `ProgFD` |

**Why.** `MapFD` from `GetAll*` is FD 0 (stdin): wrong but loud (unverified: the kernel rejects a non-BPF fd with an error). `ProgID` from `RecoverAll*` is 0: silent if compared.

**Cites.** SDK 9127cb7: `elf.go:726-730`, `1113-1131`, `1307-1325`, `1484`, `1512`. NPA 1703063: uses only `ProgID` from `GetAll*` (`pkg/ebpf/bpf_client.go:565-569`), looks maps up by name (`bpf_client.go:483`), rejects a load with empty `Maps` (`bpf_client.go:1038-1041`).

**Check.** For each new `BpfData` field read, name the API that produced it.

<a id="c6"></a>
### C6. FD ownership and stale copies

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

**Cites.** SDK 9127cb7: `pkg/maps/loader.go:268-286`, `pkg/progs/loader.go:243-260`, `elf.go:249-276`, `344-363`, `1350-1378`, `pkg/utils/utils.go:140-178`. NPA 1703063: unpins only named per-pod maps (`pkg/ebpf/bpf_client.go:977-1003`); uses `ProgFD != 0` as "loaded" (`bpf_client.go:830`). `ingressProgToPodsMap` is keyed by prog FD number (`bpf_client.go:803-811`), so it is exposed to FD reuse.

**Check.** `grep -n 'UnPinMap\|UnPinProg\|unix.Close' -r pkg` in the diff. For each, ask who else holds that FD. Reject `range bpfData.Maps { UnPinMap }`.

<a id="c7"></a>
### C7. Serialize loads that share a prefix

**Rule.** Never run two loads with the same prefix at the same time. Concurrent loads are safe only for different prefixes and distinct global names. `RecoverGlobalMaps` must not run alongside loads that use the cache.

**Why.** The SDK does not report `BPF_OBJ_PIN` failures today, and `CreateBPFMap` discards `PinMap`'s error. Map and program IDs are then read back from the pin path, not the FD. `PinMap` / `PinProg` are check, unlink, pin sequences with no lock. With a racing same-prefix load, the returned ID can belong to the other load's object while the FD is ours. Silent. Each load also allocates a verifier log buffer of about 16 MiB.

**Cites.** SDK 9127cb7: `pkg/utils/utils.go:72-81`, `pkg/maps/loader.go:220-222`, `234-261`, `elf.go:262-268`, `352-358`, `pkg/progs/loader.go:212-240`, `pkg/utils/utils.go:209-211`. NPA 1703063: per-podIdentifier lock (`pkg/ebpf/bpf_client.go:343-347`, `736-737`); recovery runs before controllers and the RPC server start (comment at `bpf_client.go:345-346`).

**Check.** For any new `LoadBpfFile*` call or new goroutine that calls the SDK: which lock or startup ordering serializes it? New code that pins directly (`PinObject`, `PinMap`, `CreateBPFMap`) must verify the pin itself, for example that the ID from `GetMapFromPinPath` equals the ID of its own FD.

<a id="c8"></a>
### C8. `LoadBpfFile*` is not transactional

**Rule.** After a failed load, treat the prefix's map pins as replaced and the FDs as leaked. Don't reload under the prefix of a live, attached program unless you will finish the swap.

**Why.** Maps are loaded and re-pinned before programs are parsed. Any later error returns `nil, nil, err`, so the caller never sees the new FDs. If the prefix belongs to an attached pod, the old program keeps its old maps, but the pins now name new empty maps. Anything that opens the map by pin (the CLI, recovery after a restart) then targets maps the datapath does not read. Silent. A retry loop leaks FDs on each failure.

**Cites.** SDK 9127cb7: `elf.go:1094-1110`, `pkg/progs/loader.go:357-361`, `elf.go:352-355`. NPA 1703063: `pkg/ebpf/bpf_client.go:1014-1021`.

**Check.** For each load site: what is attached under this prefix now, and what happens if the load fails half way?

<a id="c9"></a>
### C9. TC helpers own handle 1 on every interface that matches a prefix

**Rule.** Nothing else may install a tc filter with handle `0x1` on these interfaces. The prefix list must not match interfaces the agent doesn't own. Callers must check `GetAllAttachedProgIds`'s error.

**Why.** Prefix match is `strings.HasPrefix`. Attach uses handle 1, priority 1. Detach deletes the first filter with handle 1 at any priority. `CleanupQdiscs` deletes filters only (never qdiscs), swallows every detach error, and returns nil unless `netlink.LinkList` fails. `getAttachedProgId` logs a `FilterList` error and reports 0, so that link is missing from the result without an error. In the upgrade path, if `GetAllAttachedProgIds` fails but `CleanupQdiscs` succeeds, filters are removed and no pod is queued for re-attach (unverified end to end). The upgrade path doesn't check this error today.

**Cites.** SDK 9127cb7: `pkg/tc/tc.go:79-89`, `122-133`, `165-175`, `269-309`, `314-317`, `340-344`. NPA 1703063: prefixes `eni`, `vlan` (`pkg/ebpf/bpf_client.go:184`); upgrade path `bpf_client.go:573-577`.

**Check.** Any diff to the prefix list or the upgrade path. Any new component that adds tc filters on `eni*` or `vlan*`.

<a id="c10"></a>
### C10. Re-attach is detach plus attach, and "file exists" is ambiguous

**Rule.** Replacing the program on a hook leaves it unfiltered between detach and attach. Matching `err.Error() == "file exists"` works only while `nl.EnableErrorMessageReporting` stays false process-wide.

**Why.** `FilterAdd` and `QdiscAdd` use `NLM_F_CREATE|NLM_F_EXCL`, so an existing filter or qdisc returns EEXIST (unverified kernel behavior). The SDK has no replace API. During the gap the pod's traffic in that direction is not evaluated (unverified: an empty clsact hook passes packets). A `QdiscList` error is treated as "not installed", so `QdiscAdd` returns EEXIST, which NPA reads as a stale filter. NPA then detaches the live filter and retries; if `QdiscList` fails again, the hook is left empty. If netlink error reporting is enabled, the message gains the kernel's extack text and the string compare stops matching. Prefer `errors.Is(err, unix.EEXIST)`.

**Cites.** SDK 9127cb7: `pkg/tc/tc.go:34-41`, `56-61`, `115-118`, `135-138`, `223`. NPA 1703063: `pkg/utils/utils.go:472-477` (`IsFileExistsError`), used at `pkg/ebpf/bpf_client.go:845-853` and `890-898`. netlink v1.3.1: `filter_linux.go:304`, `qdisc_linux.go:138` (`NLM_F_EXCL`), `nl/nl_linux.go:46` (default false), `:567`, `:641` (extack wrap).

**Check.** For a new attach path: is a stale filter possible, and is the gap acceptable? If not, the SDK needs a `FilterReplace`-based API. `grep -rn EnableErrorMessageReporting .`.

<a id="c11"></a>
### C11. `CleanupQdiscs` / `GetAllAttachedProgIds` directions depend on the SDK version

**Rule.** When reviewing a caller of either function, check `go.mod`. In v1.0.19 arguments and results are pod directions. In v1.0.17 they are host-hook directions, the opposite. The signatures are identical.

**Why.** Pod ingress is the host egress hook, because the hook is on the host-side veth (SDK comment at `tc.go:283-287`). A caller written for one convention and run against the other cleans up, or reports, the wrong direction. Silent.

**Cites.** SDK 9127cb7: `pkg/tc/tc.go:288-306` (`podIngressCleanup` calls `TCEgressDetach`), `tc.go:355-374` (pod ingress read from `HANDLE_MIN_EGRESS`). SDK v1.0.17: `pkg/tc/tc.go:283-295` (`ingressCleanup` calls `TCIngressDetach`). NPA 1703063: `go.mod:8`; callers at `pkg/ebpf/bpf_client.go:573-577` pass `updateIngressProbe, updateEgressProbe`; attach inversion at `bpf_client.go:845`, `890`.

**Rollback.** A rollback runs n-1's agent and n-1's SDK, not this one's. The byte compare (`bpf_client.go:373-416`) sets an update flag only for the directions whose objects differ; an events change sets all three. With SDK v1.0.17, `CleanupQdiscs(true, false)` (pod ingress only) calls `TCIngressDetach` (v1.0.17 `tc.go:283-285`), which removes the host ingress hook's filter. That hook carries the pod egress program (`attachEgressBPFProbe` calls `TCIngressAttach`, `bpf_client.go:890`). So a change to only one direction's objects makes a rollback to an agent on v1.0.17 remove the other direction's filters. NPA at 1703063 pins v1.0.17, so the same applies to an upgrade unless the change also bumps the SDK. To make the transition change both directions, bump `NPA_FILE_VERSION` in all four tc programs ([P2](#p-change)). Whether the removed filters are re-attached is not traced end to end (unverified).

**Check.** `grep -n aws-ebpf-sdk-go go.mod` with any diff near these calls. An SDK bump changes upgrade behavior here; say so in the PR. For a one-direction change, name the n-1 versions that are safe rollback targets.

<a id="c12"></a>
### C12. Map key and value buffers must match the map's sizes exactly

**Rule.** Pointers passed to map APIs must reference at least `KeySize` / `ValueSize` bytes. Go mirrors of C structs must have the same size and padding.

**Why.** The SDK passes raw `uintptr`s with no size check. A short buffer makes the kernel read or write adjacent Go memory (unverified: kernel copies exactly `key_size` / `value_size`). Silent. A key whose padding bytes are not zeroed hashes differently (unverified: the kernel hashes all `key_size` bytes), which is why the C code memsets keys before filling them.

**Cites.** SDK 9127cb7: `pkg/maps/loader.go:296-326`, `418-439`. NPA 1703063: `pkg/utils/utils.go:28-31` (trie sizes), `utils.go:544-573` (`ConntrackKey`, `ConntrackKeyV6`, `ConntrackVal` with explicit `_` padding), `pkg/ebpf/bpf_client.go:108-110` (`pod_state`), `pkg/ebpf/c/tc.v4ingress.bpf.c:335,337` (memset). Shape tests: `pkg/ebpf/conntrack/conntrack_client_test.go:44-63` (key field names only, not sizes); `:67-77` checks `ConntrackVal` size and offset against a hard-coded 16, not against the C object.

**Check.** For any struct or constant change on either side of a map, compare the Go size with the C `key_size` / `value_size`. A privileged test that loads each ELF and compares `GetBPFmapInfo(fd).KeySize/ValueSize` with the Go sizes catches drift.

<a id="c13"></a>
### C13. Map API return semantics

**Rule.**

- `errors.Is(err, unix.ENOENT)` works only after `GetNextMapEntry`, `GetFirstMapEntry`, `GetNextMapEntryByID` and `GetFirstMapEntryByID`. Other map errors are stringified with `%s`.
- `CreateMapEntry` (`BPF_NOEXIST`) returns nil when the key already exists. It never overwrites.
- The SDK bulk APIs are not atomic: `BulkUpdateMapEntry` stops at the first failure with earlier entries already written, and `BulkRefreshMapEntries` only logs delete failures. NPA does not use them.

**Why.** An ENOENT check after a lookup never fires, so the not-found path becomes the generic error path. A caller that expects `CreateMapEntry` to set a value keeps the old one. Both silent.

**Cites.** SDK 9127cb7: `pkg/maps/loader.go:369-371`, `654-656` (bare errno), `432-434`, `687-689`, `319-321`, `341-343` (stringified), `314-317` (EEXIST), `453-498` (bulk). NPA 1703063: relies on `CreateMapEntry` for idempotency (`pkg/ebpf/bpf_client.go:1226-1243`); has its own shadow map (`pkg/ebpf/bpf_mem_map.go:91-143`). Existing ENOENT checks are not a precedent to copy: for example `conntrack_client.go:104` and `:276` follow `GetMapEntryByID` and never match.

**Check.** `grep -n 'errors.Is(err, unix.ENOENT)' -r pkg`: the preceding call must be a next-key API. Reject new uses of the SDK bulk APIs.

<a id="c14"></a>
### C14. ELF map definitions: 28-byte layout, `PIN_GLOBAL_NS` only

**Rule.** `SEC("maps")` entries must be 7 consecutive `__u32`: type, key_size, value_size, max_entries, map_flags, **pinning**, inner_map_fd. Every map a pinned program references must use `PIN_GLOBAL_NS`. Expect every load to replace the map with a new, empty one.

**Why.** The SDK strides by 28 bytes and reads pinning from bytes 20-24. libbpf's 20-byte `bpf_map_def` or iproute2's `bpf_elf_map` (sizes per their headers, not in these trees) are misread: usually the loader panics with a slice out of range, and for some map counts it misparses silently. The loop panics whenever the section leaves fewer than 24 bytes after the last 28-byte stride. Only `PIN_GLOBAL_NS` pins, and it unlinks any existing pin first. Pin types 1 and 3 are not pinned, so the same load then fails with "map ... doesn't exist" (`elf.go:263-266`). `PIN_NONE` maps have no pin, so recovery aborts the whole walk.

**Cites.** SDK 9127cb7: `elf.go:43`, `elf.go:487-497`, `pkg/maps/loader.go:226-265`, `elf.go:256-276`, `1348-1362`. The Go struct `BpfMapDef` names the 6th and 7th fields the other way round (`pkg/maps/loader.go:66-74`); the parser is what counts. NPA 1703063: `struct bpf_map_def_pvt` at `pkg/ebpf/c/tc.v4ingress.bpf.c:46-54`, `pkg/ebpf/c/v4events.bpf.c:6-14`; `.pinning = PIN_GLOBAL_NS` at `tc.v4ingress.bpf.c:113,122,135`.

**Check.** `grep -n 'struct bpf_map_def_pvt {' -A8 pkg/ebpf/c/*.c` and `grep -n '\.pinning' pkg/ebpf/c/*.c`.

<a id="c15"></a>
### C15. No CO-RE, BTF-defined maps, or global data

**Rule.** BPF C may reference only maps in its own `SEC("maps")` or globals already in the cache. Do not read kernel-internal struct fields. Only UAPI-stable layouts (`__sk_buff`, IP and TCP headers) are safe. Do not use global variables, `bpf_printk`, `SEC(".maps")` or `BPF_CORE_READ`.

**Why.** Relocation resolves a symbol by name only: local map, then cache. The SDK has no handling of `.BTF.ext`, `.maps`, `.data`, `.rodata` or `.bss`, and passes no program BTF to `BPF_PROG_LOAD`. A CO-RE field access (anything through `vmlinux.h`, unverified: depends on bpftool's `preserve_access_index` output) loads with its compile-time offset. On a kernel whose layout differs it reads another field (unverified: the verifier allows it). Silent. Global variables and `.maps` maps fail the load (observable).

**Cites.** SDK 9127cb7: `elf.go:717-736`, `pkg/progs/loader.go:293-343`. NPA 1703063: TC C includes `vmlinux.h` (`pkg/ebpf/c/tc.v4ingress.bpf.c:1`) but touches only UAPI structs. `NPA_FILE_VERSION` (`tc.v4ingress.bpf.c:477`) is a `const volatile` global that no code references; referencing it would need `.rodata` support (unverified).

**Check.** In a `.c` / `.h` diff, grep `->` on pointers from kfuncs or helpers that point into kernel memory, and grep for global non-map variables, `bpf_printk`, `SEC(".maps")`, `BPF_CORE_READ`. Pass kernel objects such as `struct nf_conn` only as opaque pointers to kfuncs.

<a id="c16"></a>
### C16. Program sections and `.text` subprograms

**Rule.** Program sections must be `xdp`, `tc_cls`, `tc_act`, `kprobe/<fn>`, `kretprobe/<fn>` or `tracepoint/<subsys>/<name>`. Each program must be a GLOBAL function, and the function name must match the constant NPA uses to rebuild the pin path. An ELF with `.text` subprograms must have one entry function that owns its whole section. Subprograms must be static `__noinline`. kfuncs must be called from the program section, so helpers that call kfuncs must be `__always_inline`.

**Why.** An unsupported section type is skipped with an Info log, so `SEC("tc")` or `SEC("classifier")` loads "successfully" with zero programs. Static functions in program sections are not loaded. The `.text` rules fail at load time only, so only a test that loads the built ELF catches them.

**Cites.** SDK 9127cb7: `elf.go:419-434`, `982-984`, `1047-1051`, `928-935`, `1034-1037`, `682-685`, `561-563` (kfunc from `.text`). NPA 1703063: `SEC("tc_cls")` (`pkg/ebpf/c/tc.v4ingress.bpf.c:321`); `utils.TC_INGRESS_PROG` / `TC_EGRESS_PROG` (`pkg/utils/utils.go:35-36`); pin path rebuilt at `utils.go:219-226`; missing program caught at `pkg/ebpf/bpf_client.go:1025-1030`.

**Check.** `grep -n 'SEC(' pkg/ebpf/c/*.c`. A function rename must update `TC_*_PROG`.

<a id="c17"></a>
### C17. kfunc resolution (SDK v1.0.18 and later)

**Rule.** Call `btf.CheckKfuncs` once at startup, not per load. Decide what the agent does if a later load of a kfunc-using ELF fails.

**Why.** Resolution is by name only (vmlinux first, then the first module that has it), with no prototype check. The resolver is process-wide. Module BTF FDs stay open for the process lifetime, so after a module such as `nf_conntrack` is unloaded and reloaded, kfunc programs fail to load until the agent restarts (per the SDK comment at `kernel.go:57-59`; kernel behavior unverified). Only successes are cached. Each failed check re-walks all kernel BTF under one mutex, which serializes every kfunc load.

**Cites.** SDK 9127cb7: `pkg/internal/btf/kernel.go:55-65`, `82-115`, `137-178`, `pkg/btf/btf.go:23-33`. NPA 1703063 uses no kfuncs. v1.0.17 has no kfunc support.

A `CheckKfuncs` error of the form `read BTF ID <n>: <errno>` comes from the walk over kernel BTF objects (`pkg/internal/btf/kernel.go:244-249`), not from the verifier. A failed program load returns only the errno; the verifier's reason is only in the SDK log ([C19](#c19)).

**Check.** Where is `CheckKfuncs` called, and how often? Is the decision made once at init, logged, and visible (see [P9](#p-gate))? When a kfunc load fails, read the SDK log before concluding why.

<a id="c18"></a>
### C18. Ring buffer: one map per `Events`, keep draining

**Rule.** Call `InitRingBuffer` once per process per ring buffer map, with a single FD. Drain the returned channel continuously.

**Why.** With several FDs, each ring overwrites the shared channel fields, so earlier channels never receive. Silent. The channel is unbuffered. A slow consumer blocks the reader, the ring fills, and `bpf_ringbuf_output` fails; NPA ignores its return, so events are lost (unverified kernel behavior). There is no public stop.

**Cites.** SDK 9127cb7: `pkg/events/events.go:153-158`, `161`, `234`. NPA 1703063: one FD (`pkg/ebpf/events/events.go:99-102`); C ignores the output result (`pkg/ebpf/c/tc.v4ingress.bpf.c:419-423`).

**Check.** Exactly one `InitRingBuffer` call. No new blocking work in the receive loop. The existing loop already calls `PutLogEvents` synchronously when CloudWatch logs are enabled (`pkg/ebpf/events/events.go:197`, `:283`); don't add to it.

<a id="c19"></a>
### C19. Some failures appear only in the SDK's own log

**Rule.** When diagnosing SDK behavior, read `/var/log/aws-routed-eni/ebpf-sdk.log` (or `$AWS_EBPF_SDK_LOG_FILE`) as well as the agent log. SDK errors do not carry verifier output.

**Why.** Log-only failures: pin syscall failures, `CleanupQdiscs` detach errors (only `FILTER_CLEANUP_FAILED` is logged; others are dropped), per-link `FilterList` errors, map close failures, and module BTF parse failures (log-only when the kfunc is found elsewhere; included in the error when it is not). The verifier log is logged at Info; the returned error carries only the errno. Some recovery errors carry no context ("failed to get err", "unable to get FD").

**Cites.** SDK 9127cb7: `pkg/logger/logger.go:28-31`, `pkg/progs/loader.go:347-353`, `pkg/tc/tc.go:290-306`, `314-317`, `pkg/internal/btf/kernel.go:157`, `186-187`, `elf.go:1346`, `1361`, `1508`. NPA 1703063: `sdkAPIErr` labels (`pkg/ebpf/bpf_client.go:77-83`) cannot see these cases.

**Check.** For a new failure mode, ask which log line or metric shows it in production. If only the SDK log, say so in the PR.

<a id="c20"></a>
### C20. Fixed bpffs paths are duplicated in NPA

**Rule.** `/sys/fs/bpf/` must be a bpffs mount. Nothing may change the SDK's `PROG_BPF_FS` / `MAP_BPF_FS` without changing NPA's copies and its index-based parser.

**Why.** Only the recovery APIs check the bpffs magic. The load path just creates directories, so without bpffs the pins fail (unverified: the kernel rejects `BPF_OBJ_PIN` outside bpffs; the SDK does not report it, see [C7](#c7)) and the same load fails with "map ... doesn't exist". A change in path depth breaks `pinPathName[7]`.

**Cites.** SDK 9127cb7: `pkg/constants/constants.go:92-94`, `111-112`, `elf.go:1170`, `1257`. NPA 1703063: `pkg/utils/utils.go:33-34`, `207-217` (`[7]`); `pkg/ebpf/bpf_client.go:48-49` (`CONNTRACK_MAP_PIN_PATH`, `POLICY_EVENTS_MAP_PIN_PATH`), compared literally at `bpf_client.go:449-458`; also `pkg/ebpf/events/events.go:30`, `pkg/ebpf/conntrack/conntrack_client.go:16`, `pkg/ebpf/healthcheck.go:25`.

**Check.** `grep -rn '/sys/fs/bpf' pkg` in the diff, and any SDK bump that touches `constants.go`.

<a id="parity"></a>
## 4. v4/v6 parity

There is no shared header (`helper.h` exists but nothing includes it) and almost no shared Go code between families. Unit tests mostly exercise v4: `NewMockBpfClient` hard-codes `hostMask: "/32"` (`pkg/ebpf/bpf_client_mock.go:13-24`), and no unit test calls `TC_V6_*`, `EVENTS_V6_BINARY`, `MapWalkv6` or `Cleanupv6ConntrackMap` (the v6 key has only a field-name shape test, `conntrack_client_test.go:55`). An IPv6 integration run is the only check for most v6 paths.

<a id="parity-table"></a>
### What must change together (NPA 1703063)

| Area | v4 | v6 | Keep in sync |
|---|---|---|---|
| TC programs | `pkg/ebpf/c/tc.v4ingress.bpf.c`, `tc.v4egress.bpf.c` | `tc.v6ingress.bpf.c`, `tc.v6egress.bpf.c` | Whole program, `NPA_FILE_VERSION` |
| Events programs | `pkg/ebpf/c/v4events.bpf.c` | `v6events.bpf.c` | Define `aws_conntrack_map` (key size comes from this file) and `policy_events` |
| `struct conntrack_key` | `tc.v4ingress.bpf.c:80-88`, `tc.v4egress.bpf.c:81-89`, `v4events.bpf.c:31-39` | `tc.v6ingress.bpf.c:80-88`, `tc.v6egress.bpf.c:81-89`, `v6events.bpf.c:32-40` | Go: `pkg/utils/utils.go:544-566` |
| `struct conntrack_value` | four tc files, both events files | same | Go: `utils.go:568-573` |
| `struct data_t` (ring record) | four tc files, both events files | same | Go: `pkg/ebpf/events/events.go:67-89` |
| Trie key and value | `__u32 ip` / `__u8 ip[4]` | `__u8 ip[16]` | `MAX_PORT_PROTOCOL 24` in all four tc files; Go `utils.go:28-31` (`TRIE_VALUE_LENGTH` depends on it), `605-613` |
| Binary and CLI names | `pkg/ebpf/bpf_client.go:35-47` | same | `pkg/utils/cp/cp.go:11-14` duplicates the CLI names |
| Family selection | `bpf_client.go:170-179` | same | A second events switch at `bpf_client.go:232-235` |
| Change detection | `bpf_client.go:378`, `397`, `405`, `409` | same | Each name check lists both families |
| Conntrack GC | `pkg/ebpf/conntrack/conntrack_client.go:79-246` | `:248-423` | v4 compares through `ConvIPv4ToInt(ConvIntToIPv4(x))`; v6 compares raw bytes |
| Event decode and log text | `pkg/ebpf/events/events.go:220-277` | same | Both formats |
| CLI | `pkg/clihelper/show.go:155-314`, `cmd/cli/` | `show.go:317-442`, `cmd/cliv6/` | v6 is a subset today |
| Rule processing | `pkg/fwruleprocessor/fw_rule_processor.go`, `cidr_trie.go:12-42` | same | `hostMask`, `shouldSkipRule`, v4-mapped v6 |
| Catch-all entry | `controllers/policyendpoints_controller.go:794-806` (`0.0.0.0/0`) | `::/0` | Only the PE reconciler takes `enableIPv6` |
| Conversion helpers | `pkg/utils/utils.go:516-532` | `utils.go:534-542`, `585-603`, `628-640` | `ConvTrieV6ToByte` hard-codes `*[20]byte` |
| Build and image | `Makefile:124-125`, `147-166`, `Dockerfile:53-60` | same | Both CLIs, all six `.o` files |
| Integration tests | `--ip-family` (`test/framework/options.go:36`) | `curl -6` in `ValidateConnection` (`test/framework/resources/k8s/pod/resource.go:245`) | Per-family targets and host masks |

Expected family-specific behavior at 1703063: v6 ingress and egress let ICMPv6, and Hop-by-Hop followed by ICMPv6, through unconditionally (`tc.v6ingress.bpf.c:357-368`, `tc.v6egress.bpf.c:368-379`). Expected direction differences within one family: map names, `handle_ingress` / `handle_egress`, trie key from `saddr` (ingress) or `daddr` (egress), `owner_ip`, `is_egress`, the egress-only `baseline_tier_priority` out-param of `evaluateClusterPolicyByLookUp`, `effective_action`, the unused `NETWORK_POLICY_TIER_PRIORITY`, and the dead `dest_ip` / `src_ip` local in the v4 files.

<a id="parity-diff"></a>
### Running the diff helper

`hack/v4v6-diff.py` diffs the C sources by family. Run the commands from the NPA root. It strips comments and whitespace, rewrites family tokens to a common form, and diffs each C file pair. Identifiers ending in `_v4` or `_v6` are rewritten to `_vX`, so family-named helpers and their call sites match. The trie key fill (four byte stores in v4, a 16-byte loop in v6) collapses to one token only when it has exactly the expected shape; any other edit there shows as a hunk. Hunks carry original line numbers on both sides.

Code shared by both families in one header is not in a file pair. `--funcs` diffs each `foo_v4` / `foo_v6` function pair defined in one file and reports a function without its twin. `--all` runs it on every `pkg/ebpf/c/*.h` except `vmlinux.h`; a header with no such functions prints nothing.

```bash
# All three pairs, then the _v4/_v6 functions in every header
python3 -I hack/v4v6-diff.py --all .

# One pair
python3 -I hack/v4v6-diff.py pkg/ebpf/c/tc.v4ingress.bpf.c pkg/ebpf/c/tc.v6ingress.bpf.c

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

At 1703063 the events pair has no remaining hunks and no header has `_v4`/`_v6` functions. The ingress pair has 12 baseline hunks and the egress pair 14:

- Both: the ICMPv6 bypass (the only real family difference); the dead v4 local (`dest_ip[4]` in ingress, `src_ip[4]` in egress), its memset and byte fill; reorders of `struct data_t evt`, `flow_key.dest_ip`, `evt.dest_ip` and `reverse_flow_key.dest_ip`.
- Ingress: the duplicate v6 conntrack lookup (`tc.v6ingress.bpf.c:434`, `437`).
- Egress: two hunks where v4 switches on `effective_action` and v6 switches on `admin_tier_action` or `baseline_tier_action`.

A change should add no new hunk unless the PR says why it is family-specific. Diff against the merge base, as above, to separate new hunks from these. In a `--funcs` hunk, expect only address types and copies (`__be32` against `struct in6_addr *`, assignment against `__builtin_memcpy`). Known noise: a reordered statement appears as a paired insert and delete of the same text, and a lone `}` can join a neighboring hunk.

<a id="precedents"></a>
## 5. Precedents

Use the existing mechanism before adding a new one. All citations are NPA 1703063.

<a id="p-hostname"></a>
### P1. One host name for a variant binary

`InstallBPFBinaries` installs the v6 CLI under the v4 name: `if plugin == EKS_V6_CLI_BINARY { targetPlugin = EKS_CLI_BINARY }` (`pkg/utils/cp/cp.go:73-76`). Inside the container the binary keeps its `-v6` name (`Dockerfile:53-54`). Host-side tests always call `/opt/cni/bin/aws-eks-na-cli` (`test/integration/restart/conntrack_map_restart_test.go:175`). Tests that exec inside the container must pick the name by family.

For a new object variant, install the selected object under the existing name (for example `tc.v4ingress.bpf.o`). The byte compare in [P2](#p-change) then handles upgrade and downgrade without new logic.

<a id="p-change"></a>
### P2. Change detection: byte compare and `NPA_FILE_VERSION`

- `checkAndUpdateBPFBinaries` compares each shipped file in the container CWD with the host copy in `/host/opt/cni/bin/`: `cmp.Equal(currentProbe, existingProbe)` (`pkg/ebpf/bpf_client.go:373-416`). There is no version ID. Read errors are only logged.
- An events change sets all three update flags (`bpf_client.go:397-403`). Global-map recovery is then skipped (`bpf_client.go:439`) and every pod is reattached with default state (`bpf_client.go:602-649`).
- CLIs are excluded from the compare (`bpf_client.go:378-380`).
- Install runs after the compare: copy to `<dst>.tmp`, then rename (`pkg/utils/cp/cp.go:45-66`, called at `bpf_client.go:205` after the compare at `:196`). Install errors are logged per file.
- To force a reload without a logic change, bump `const volatile __u32 NPA_FILE_VERSION` in all four tc programs (`tc.v4ingress.bpf.c:477`, `tc.v4egress.bpf.c:494`, `tc.v6ingress.bpf.c:483`, `tc.v6egress.bpf.c:492`; added in commit `e51dfe8` "bump eBPF file version"). No Go code reads it. Its purpose is to change the object bytes (unverified, inferred from use). The events files do not have it.
- The agent loads objects by bare filename from the container CWD (`bpf_client.go:383`, `1014`). A new object must be in `bpfBinaries` (`bpf_client.go:179`), `Makefile` `build-bpf` (`:160-166`), `Dockerfile` `COPY` (`:55-60`), and the name checks at `bpf_client.go:378-411`. If a file is missing from both the image and the host, both reads return nil, `cmp.Equal` reports equal, and no reload is triggered; the later `LoadBpfFile` then fails.
- Any edit to a BPF C file changes the object's bytes, even when the program's logic does not change. The objects are built with `-g` (`Makefile:160-166`) and shipped unstripped (`Dockerfile:55-60`). Adding one comment line near the top of `tc.v4ingress.bpf.c` leaves the `tc_cls` instructions and `.BTF` identical but changes `.BTF.ext` and `.debug_line` (line info), so the object differs (built with the `build-bpf` flags, clang 15.0.7 on AL2023). An `#include`, a moved line or a new local has the same effect, and a new type or function also changes `.BTF` (inferred). So every node reloads that object on upgrade: each pod's program in that direction is detached and re-attached ([C10](#c10)), and that direction's pod state is set to the mode default (`bpf_client.go:602-649`, [P10](#p-mode)). Say so in the PR.
- To check, build the objects at the merge base and at the change with `make build-bpf`, then `cmp` each `.o`. Build both in the same directory path: the object also records the build directory, so the same source built in two directories differs. `make build-bpf` needs `pkg/ebpf/c/vmlinux.h`, which `make vmlinuxh` generates on a Linux host with `bpftool` (`Makefile:139-140`).
- If only one direction's objects change, a rollback to an agent on SDK v1.0.17 removes the other direction's filters ([C11](#c11)). When that matters, bump `NPA_FILE_VERSION` in all four tc programs so both directions are reloaded, as in commit `e51dfe8`.
- A new header in `pkg/ebpf/c/` is ignored by `.gitignore` (`*.h`, line 3). It needs a `!pkg/ebpf/c/<name>.h` exception or `git add -f`; `helper.h` is tracked even though the rule matches it. Check that the PR actually contains the header.
- Crash window: binaries are installed (`:205`) before the new objects are loaded (`:245`). If the agent exits in between, the next start sees equal files and recovers the old pinned state (outcome unverified; raised on [#610](https://github.com/aws/aws-network-policy-agent/pull/610#discussion_r3677714530)).

<a id="p-marker"></a>
### P3. One-time host migration with a marker file

`pkg/ebpf/legacy_pin_migration.go` is the pattern:

- Marker `/var/run/aws-node/.npa_format_v2` (`:21`). Present means no-op (`:39-43`).
- A missing input returns nil without writing the marker, so it retries on the next start (`:45-48`).
- Any failed step returns an error and skips the marker (`:92-94`). The marker is written only on full success (`:96-103`).
- Directories and marker path are parameters (`migrateLegacyPinsFromCNIState(progsDir, mapsDir, ipamPath, markerPath)`, `:38`), so tests use `t.TempDir()` (`legacy_pin_migration_test.go:30-220`).
- Called first in `recoverBPFState`; errors are not fatal (`bpf_client.go:428-435`).
- The old algorithm lives in one marked function: `utils.LegacyGetPodIdentifier` (`pkg/utils/utils.go:190-205`, with a removal TODO).

<a id="p-map"></a>
### P4. Adding a per-pod map

Define the map in C with `bpf_map_def_pvt` and `PIN_GLOBAL_NS` in each relevant tc program ([C14](#c14)). Add a name constant next to `TC_INGRESS_MAP` (`pkg/utils/utils.go:37-42`). Then add it in these places, or it is lost on restart or leaked on delete:

1. `NamespacedBPFMaps` (`pkg/utils/utils.go:52-62`).
2. `renamePinFamily` (`pkg/ebpf/legacy_pin_migration.go:117-126`).
3. `deleteBPFProgramAndMaps` (`pkg/ebpf/bpf_client.go:963-1006`), with a pin path helper in `pkg/utils/utils.go:228-245`.
4. `recoverBPFState` map lookups (`bpf_client.go:481-548`), if the map has a userspace shadow map.

<a id="p-recovery"></a>
### P5. Recovery order at startup

`NewBpfClient`: compare (`bpf_client.go:196`), install (`:205`), `recoverBPFState` (`:215`), load events only if needed (`:230`), start conntrack GC (`:293-297`). `main.go` then calls `ReAttachEbpfProbes()` before controllers and the RPC server start. Recovery errors are logged and counted, never fatal (`bpf_client.go:466-470`). A `RecoverGlobalMaps` error returns early (`:440-445`), so per-pod recovery and reattach collection are skipped for that start. Readiness checks cover global map pins and bpffs (`main.go:138-147`, `pkg/ebpf/healthcheck.go:29-66`). New pinned state should be recovered here, not in a parallel path.

A new load that runs before the events load (`:230-245`) relocates against the previous agent's global maps, whose conntrack value layout changed in v1.4.3 ([C4](#c4)). Place validation or probe loads after the events load, or skip them when `eventsUpdateRequired` is set or a global map is missing.

<a id="p-metrics"></a>
### P6. Metrics labels

- SDK latency: `sdkAPILatency` (`awsnodeagent_aws_ebpf_sdk_latency_ms`, labels `api`, `error`; `bpf_client.go:69-75`). Pattern: `start := time.Now()` ... `sdkAPILatency.WithLabelValues("attachIngressBPFProbe", fmt.Sprint(err != nil)).Observe(msSince(start))` (`bpf_client.go:777-780`).
- SDK errors: `sdkAPIErr` (`awsnodeagent_aws_ebpfsdk_error_count`, label `fn`; `bpf_client.go:77-83`). Values follow `<operation>[-<qualifier>]`, for example `LoadBpfFile-NoPinPath` (`bpf_client.go:1028`).
- Process-wide SDK counters use `prometheus.NewCounterFunc` (`bpf_client.go:89-103`).
- Registration is guarded by a package bool (`bpf_client.go:116-124`) on controller-runtime's `metrics.Registry`.
- Prefixes are already inconsistent (`awsnodeagent_aws_ebpf_sdk_`, `awsnodeagent_aws_ebpfsdk_`, unprefixed `network_policy_drop_*` in `pkg/ebpf/events/events.go:46-60`). Prefer a new label value on an existing metric. A new metric should join an existing family, not add a prefix.
- `msSince` returns fractional milliseconds (`bpf_client.go:112-114`). Don't reintroduce integer `Duration` division ([#689](https://github.com/aws/aws-network-policy-agent/pull/689#discussion_r4277219690)).

<a id="p-logging"></a>
### P7. Logging

- Each agent package that logs defines `func log() logger.Logger { return logger.Get() }` (`bpf_client.go:64-66`). Use it, not `fmt.Println` (CLI output in `pkg/clihelper` excepted).
- The flag default is `debug` (`pkg/config/controller_config.go:17`), so Debug lines are not free at scale.
- Policy verdict logs: DENY at Info, ACCEPT and EXPIRED/DELETED at Debug (`pkg/ebpf/events/events.go:238-246`).
- Flow log text differs by family (`events.go:241` vs `:270`). Anything that greps flow logs must match both `Verdict: DENY` and `Verdict DENY`.
- The logger is a zap `SugaredLogger` (`pkg/logger/zaplogger.go:27`). Its format methods follow `fmt.Sprintf` (zap `sugar.go:378`), so `%w` renders as `%!w(...)`. Use `%v`.

<a id="p-flags"></a>
### P8. Flags and environment variables

- Agent flag: constant, default and field in `pkg/config/controller_config.go:11-61`, bound in `BindFlags` (`:63-85`), validated in `ValidControllerFlags` (`:88-94`), parsed in `main.go:197-208`.
- `NewBpfClient` takes ten positional parameters (`bpf_client.go:149-150`), several adjacent `bool`s. Check argument order when adding one. `NewMockBpfClient` bypasses the constructor (`bpf_client_mock.go:13-24`), so new fields need setting there too.
- A new flag is a one-way door. Managed add-on users can change agent settings only through the add-on configuration, and exposing a flag there has needed product approval. Each flag also multiplies the configurations tested at major releases. Reviewer's question: can the change ship without a flag? If a test needs a different code path, use a test-only mechanism, such as the test agent image, not a product flag.
- For a behavior gated by kernel or capability ([P9](#p-gate)) with no flag, turning it off means rolling back the agent. Ask whether that is acceptable, and make the PR say so.
- Delivery: the VPC CNI chart sets agent flags (`amazon-vpc-cni-k8s` at `a149c83c`, `charts/aws-vpc-cni/templates/daemonset.yaml:152-162`, `nodeAgent.*` values). A new flag needs a chart change in that repo to be settable.
- The only env var is `MY_NODE_NAME` (`pkg/ebpf/events/events.go:211`), from the downward API (chart `daemonset.yaml:147-151`).
- `NetworkPolicyMode` and `MultiNICEnabled` come from ipamd over gRPC, not flags (`main.go:210-234`).

<a id="p-gate"></a>
### P9. Feature gating by kernel or capability

The agent has no runtime kernel, BTF or capability gate at 1703063. A change that adds the first one sets the precedent. It should decide once at init, log the decision, expose it in a log line or metric, and have a nightly-matrix test for both sides. Deciding once avoids a mix of program variants on one node. Test-side precedent: `test/integration/policy/verifier_budget_test.go:278-290` reads `node.Status.NodeInfo.KernelVersion`, records it with `AddReportEntry`, and `Skip`s with the reason.

CI can't cover both sides of a kernel gate by itself. Test clusters are AL2023 only (`scripts/eks-test-cluster.sh:39`, `amiFamily: AmazonLinux2023`), and the nightly workflow is "Nightly AL2023 Kernel Tests" (`.github/workflows/nightly-kernel-tests.yaml:1`). If every AL2023 kernel passes the gate, the other side has no integration coverage, and once all CI kernels pass, the ungated object is never loaded in CI. Cover the other side with a privileged test that loads each shipped object on the node under a throwaway prefix, or with a test-only override that forces the other path on one leg. A unit test with the gate mocked does not load the object.

<a id="p-mode"></a>
### P10. Strict mode, default state, and locking

- Read the mode with `GetNetworkPolicyMode()` / `utils.IsStrictMode` (`bpf_client.go:651-653`, `pkg/utils/utils.go:74-102`).
- Network-policy pod state defaults to `DEFAULT_DENY` in strict mode (`pkg/rpc/rpc_handler.go:93-97`, `bpf_client.go:603-606`). Cluster-policy state is `DEFAULT_ALLOW` on CNI ADD (`rpc_handler.go:99`, `:169`) and `POLICIES_APPLIED` when CNP rules exist (`controllers/clusterpolicyendpoints_controller.go:318-331`). But `ReAttachEbpfProbes` writes the mode default, `DEFAULT_DENY` in strict, to the cluster-policy key too (`bpf_client.go:621`, `:643`).
- Per-pod state is guarded by `podIdentifierLocks` (`bpf_client.go:343-347`). It is not re-entrant. Helpers that need it held carry a `Locked` suffix. Compute map entries before taking it.

<a id="p-tests"></a>
### P11. Where tests go and which CI runs them

Unit tests: `make test` runs `go test ./pkg/... ./controllers/...` (`Makefile:87-89`). Mock the SDK with its gomock mocks (`pkg/ebpf/bpf_client_test.go:17-20`). Controllers use `MockBpfClient` (`pkg/ebpf/bpf_client_mock.go`). Split pure logic out so it runs without a kernel (`entryActiveFromRead`, `pkg/ebpf/conntrack/conntrack_client.go:19-28`). The PR unit job never compiles the C; only the `docker-build` job does, on pull requests (`.github/workflows/pr-tests.yaml`). Verifier rejections show only on a real kernel.

Integration suites live in `test/integration/<suite>/`, one ginkgo suite per directory, built by `make build-test-binaries` (`Makefile:346-350`). Placement decides where a test runs:

| Suite | PR `/test cyclonus` (`scripts/run-cyclonus-tests.sh`) | Nightly kernel (`scripts/run-kernel-smoke-tests.sh`) |
|---|---|---|
| `policy` | yes (`:118`) | yes (`:35`) |
| `ebpf` | yes when `RUN_EBPF_TESTS=true`, the default (`:120-123`) | **no** |
| `clusternetworkpolicy` | yes (`:125-127`) | no |
| `restart` | only if `RUN_RESTART_TESTS=true`; default false, no workflow sets it (`:129-131`) | no |
| `strict` | yes, last (`:133-139`) | yes, last (`:37-39`) |
| `leak`, `upgrade`, `soak/port-reuse` | not run by any script or workflow | no |

All legs run on IPv4 and IPv6. The nightly kernel workflow (`.github/workflows/nightly-kernel-tests.yaml`) runs daily on AL2023 kernel lines and runs only `policy` and `strict`. A test in `test/integration/ebpf/` needs `run-kernel-smoke-tests.sh` extended ([Theme 16](#themes)). The strict suite mutates aws-node, so it must stay last. Restart tests assume default allow, so they run before it ([#706](https://github.com/aws/aws-network-policy-agent/pull/706#issuecomment-6227325153)). Shared helpers are in `test/framework` (`BuildBPFCheckPod`, `ParseLoadedEBPFData` in `test/framework/utils/bpf.go`).

Some CI text says the ebpf suite skips IPv6 (`pr-cyclonus-tests.yaml:192`, `run-cyclonus-tests.sh:10`, `:121`). The suite has no family-wide skip: `conntrack_poisoning_test.go:26-28` states it runs on both, and the only `Skip` in the suite is an IPv6-only spec skipping IPv4 (`hop_by_hop_icmpv6_test.go:41`). Check which specs ran from the suite code and the run's report, not from the summary label.

Tests that read the node's conntrack table should look the tuple up, not scan it. `/proc/net/nf_conntrack` is generated while the table is walked, so a read can skip entries when others are inserted or deleted during it (kernel behavior unverified). This was measured: on a node whose table churned up to 1,841 entries, 8 of 300 reads missed a long-lived entry; on a quiet table, none did. Look the tuple up over netlink with `conntrack -G` instead. The EKS AL2023 AMI installs the `conntrack` package (`amazon-eks-ami` `templates/al2023/provisioners/install-worker.sh:56`). Run it from a privileged check pod with the host root at `/host`, such as `BuildBPFCheckPod` (`test/framework/utils/bpf.go:15-35`): `chroot /host conntrack -G -p tcp -s <src> -d <dst> --sport <sport> --dport <dport>`.

Test pods also need distinct pod identifiers when the test expects separate programs or maps ([P12](#p-podid)).

<a id="p-podid"></a>
### P12. Pod identifiers

`GetPodIdentifier` (`pkg/utils/utils.go:177-188`) turns a pod name and namespace into the key for a pod's BPF state:

- It drops the name's last `-` segment: `client-7d9f-abcde` and `client-7d9f-xyz12` both give `client-7d9f@<ns>`. A name without `-` is kept whole.
- It replaces `.` with `_` (`:178-181`), which collides with the SDK's split of pin names at the first `_` ([C1](#c1)).

So pods that differ only in the last segment, such as Deployment replicas, share one identifier. On a node they share one set of BPF programs and policy maps: `attachIngressBPFProbe` reuses the program loaded for the identifier (`pkg/ebpf/bpf_client.go:825-842`, same for egress), and the pin paths are derived from the identifier (`utils.go:219-245`). Locks and per-pod state are keyed by it too ([P10](#p-mode)).

For tests, give pods that need separate programs or maps names that differ before the last `-`, for example `client-a-0` and `client-b-0`, and use no `.` in names. For code, ask whether a change keys new state by pod identifier or by pod (`GetPodNamespacedName`, `utils.go:165-171`), and whether two pods that share an identifier can need different values.

<a id="p-cache"></a>
### P13. Cached reads in the reconcilers

The PolicyEndpoint and ClusterPolicyEndpoint reconcilers read from the informer cache with `client.UnsafeDisableDeepCopy` (`controllers/policyendpoints_controller.go:123-124`, `:164`, `:555`, `:674`, `:821`; `controllers/clusterpolicyendpoints_controller.go:80-81`, `:120`, `:370`, `:607`). The returned objects are shared with the cache and must not be mutated. Rule derivation passes `slices.Clip` of `Except` and `Ports`, so an append reallocates, but the existing elements and the `Protocol` / `Port` / `EndPort` pointers inside each port still belong to the cache (comments at `policyendpoints_controller.go:562-566`, `clusterpolicyendpoints_controller.go:377-381`). `TestFirewallRuleDerivation_LeavesCachedObjectsUnchanged` (`controllers/deepcopy_bench_test.go:261`) checks that deriving rules leaves cached objects unchanged.

For a change in these paths, check that no code writes through a value reached from a cached object, including in `pkg/fwruleprocessor`. A new read path should either keep the option and treat the result as read-only, or drop it. Extend that test when rule processing changes.

<a id="themes"></a>
## 6. Recurring review themes

Roughly ordered by how often maintainers raised them (approximate, hand-tagged counts).

| # | Theme | Reviewer's question | Examples |
|---|---|---|---|
| 1 | Tests give real signal | Does the test fail on main, pass with the change, call production code, and avoid sleeps and absolute counts? | [#614](https://github.com/aws/aws-network-policy-agent/pull/614#discussion_r3598831431), [SDK #176](https://github.com/aws/aws-ebpf-sdk-go/pull/176#discussion_r4343380166) |
| 2 | v4/v6 parity | Is the change in both families (C, GC, CLI, tests), and was it run on IPv6? | [#584](https://github.com/aws/aws-network-policy-agent/pull/584#pullrequestreview-4348586222), [#682](https://github.com/aws/aws-network-policy-agent/pull/682#discussion_r4355500501) |
| 3 | Log volume and correctness | Does the line fire per entry, per pod or per retry at debug default? Is it logged at several layers? | [#623](https://github.com/aws/aws-network-policy-agent/pull/623#discussion_r3772059282), [#627](https://github.com/aws/aws-network-policy-agent/pull/627#discussion_r4343154655) |
| 4 | Upgrade and downgrade | What happens to pinned state, filters and conntrack on n to n+1, n to n-1, and a crash mid-upgrade? | [#576](https://github.com/aws/aws-network-policy-agent/pull/576#issuecomment-4501362883), [#576](https://github.com/aws/aws-network-policy-agent/pull/576#discussion_r3359126004) |
| 5 | Reuse existing helpers | Is there already a helper, script or framework function? Is new logic written once, not copied? | [#584](https://github.com/aws/aws-network-policy-agent/pull/584#discussion_r3320444420), [#610](https://github.com/aws/aws-network-policy-agent/pull/610#discussion_r3679133941) |
| 6 | Retries terminate | Will each returned or retried error resolve? Is it matched by type or sentinel, not text? | [#690](https://github.com/aws/aws-network-policy-agent/pull/690#discussion_r4305104606), [#627](https://github.com/aws/aws-network-policy-agent/pull/627#discussion_r4342500099) |
| 7 | Recovery after restart | After a crash between any two steps, is state rebuilt exactly, with markers written last? | [#576](https://github.com/aws/aws-network-policy-agent/pull/576#discussion_r3337784352), [#566](https://github.com/aws/aws-network-policy-agent/pull/566#pullrequestreview-4232618343) |
| 8 | Comments and PR description | Do comments state current behavior, without history? Does the description match the code and list test results? | [#690](https://github.com/aws/aws-network-policy-agent/pull/690#issuecomment-6243838959), [#605](https://github.com/aws/aws-network-policy-agent/pull/605#issuecomment-5260978219) |
| 9 | Performance numbers | Are before/after numbers attached (pprof or flame graphs, heap at rest, memory)? | [#623](https://github.com/aws/aws-network-policy-agent/pull/623#pullrequestreview-4777192709), [#627](https://github.com/aws/aws-network-policy-agent/pull/627#discussion_r4343183533) |
| 10 | Metrics measure the right thing | Does the timer cover only what it names, keep sub-ms precision and outliers, and avoid duplicating built-in metrics? | [#689](https://github.com/aws/aws-network-policy-agent/pull/689#discussion_r4277202698), [#690](https://github.com/aws/aws-network-policy-agent/pull/690#discussion_r4305142623) |
| 11 | Syscall memory safety | Is each `unsafe.Pointer` to `uintptr` conversion inside the syscall expression? Is `KeepAlive` on the real object? | [#610](https://github.com/aws/aws-network-policy-agent/pull/610#discussion_r3634710968), [SDK #176](https://github.com/aws/aws-ebpf-sdk-go/pull/176#discussion_r4343396756) |
| 12 | SDK naming assumptions | Does a new map name or pod identifier fit the SDK's `_` parsing, stay unique across valid pod names, and is the map registered? | [#704](https://github.com/aws/aws-network-policy-agent/pull/704#discussion_r4365251642), [#576](https://github.com/aws/aws-network-policy-agent/pull/576#discussion_r3337784351) |
| 13 | Right layer | Should this live in the SDK or the controller? Does it need an SDK release first? | [#690](https://github.com/aws/aws-network-policy-agent/pull/690#discussion_r4305115662), [#627](https://github.com/aws/aws-network-policy-agent/pull/627#discussion_r4182178666) |
| 14 | C, Go and pinned layouts agree | Do C struct, Go mirror, copy sites and pinned map match? Is no old encoded value reused with a new meaning? | [#584](https://github.com/aws/aws-network-policy-agent/pull/584#discussion_r3314518432), [#682](https://github.com/aws/aws-network-policy-agent/pull/682#discussion_r4355507085) |
| 15 | Real concurrency | Is the concurrency real (reconciler workers, CNI RPC path), or is a sync primitive unnecessary? | [#657](https://github.com/aws/aws-network-policy-agent/pull/657#discussion_r3816626577), [SDK #152](https://github.com/aws/aws-ebpf-sdk-go/pull/152#discussion_r3692095754) |
| 16 | Kernel matrix | Are new eBPF tests in the nightly kernel workflow? Which kernels and OSes were tested? | [#704](https://github.com/aws/aws-network-policy-agent/pull/704#discussion_r4338695694), [#558](https://github.com/aws/aws-network-policy-agent/pull/558#issuecomment-4556598415) |
| 17 | Strict mode and default state | Is it correct in strict and standard mode, for NP and CNP state? | [#682](https://github.com/aws/aws-network-policy-agent/pull/682#discussion_r4189768987), [#706](https://github.com/aws/aws-network-policy-agent/pull/706#issuecomment-6227325153) |
| 18 | Multi-NIC | Is `INTERFACE_COUNT_UNKNOWN` a warning in reconcilers and a failure in CNI ADD? | [#690](https://github.com/aws/aws-network-policy-agent/pull/690#discussion_r4305204640) |
