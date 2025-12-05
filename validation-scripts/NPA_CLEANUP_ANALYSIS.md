# AWS Network Policy Agent - Conntrack Cleanup Analysis

## Source Code Investigation

I analyzed the AWS Network Policy Agent source code to understand the actual cleanup logging patterns.

### Repository
- **URL**: https://github.com/aws/aws-network-policy-agent
- **File**: `pkg/ebpf/conntrack/conntrack_client.go`
- **Functions**: `CleanupConntrackMap()` and `Cleanupv6ConntrackMap()`

## Cleanup Process Flow

### 1. Initial Check
```go
log().Info("Check for any stale entries in the conntrack map")
```

### 2. Two-Phase Approach

#### Phase A: First Run (Hydration)
If `hydratelocalConntrack == true`:
- Reads all entries from eBPF map
- Populates local cache: `localConntrackV4Cache`
- Logs: `"hydrated local conntrack cache"`
- Sets `hydratelocalConntrack = false`

#### Phase B: Subsequent Runs (Cleanup)
If `hydratelocalConntrack == false`:
- Reads kernel conntrack table via netlink
- Builds `kernelConntrackV4Cache` from kernel data
- Compares local cache vs kernel cache
- For entries in local but NOT in kernel:
  - Logs: `"Conntrack cleanup Delete - {details}"`
  - Deletes from eBPF map
- Logs: `"Done cleanup of conntrack map"`
- Sets `hydratelocalConntrack = true` for next cycle

## The Race Condition Window

```
T=0:     Cleanup starts: "Check for any stale entries..."
T=0-2s:  Reading kernel conntrack via netlink (SNAPSHOT taken)
T=2-4s:  Comparing local vs kernel cache
         ↓ RACE WINDOW: New connections here get missed!
T=4s:    Deleting stale entries from eBPF map
T=5s:    "Done cleanup of conntrack map"
```

### Why the Race Occurs

1. **Snapshot is static**: Taken at T=0-2s
2. **Processing takes time**: T=2-4s to compare caches
3. **New connection during processing**:
   - Creates kernel entry at T=3s
   - Creates eBPF entry at T=3s
   - BUT: Snapshot from T=0-2s doesn't have it
4. **Deletion based on old snapshot**:
   - At T=4s, entry found in local cache but NOT in snapshot
   - Incorrectly identified as "stale"
   - Deleted from eBPF map
5. **Response packet denied**:
   - Response arrives at T=5s
   - eBPF lookup fails (entry was deleted)
   - Traffic denied!

## Log Patterns for Detection

### Primary Patterns (AWS NPA Specific)
```python
r"Check for any stale entries in the conntrack map"  # Cleanup start
r"Done cleanup of conntrack map"                     # Cleanup end
r"Conntrack cleanup Delete"                          # Individual deletions
r"hydrated local conntrack cache"                    # Cache hydration
```

### Fallback Patterns (Generic)
```python
r"cleanup.*conntrack"
r"conntrack.*cleanup"
```

## Detection in the Script

The updated script now looks for these exact AWS NPA log messages:

```python
def detect_cleanup_cycle(self):
    logs = self.kube.get_npa_logs(
        self.config.npa_namespace,
        self.config.npa_pod_label,
        since="10m"
    )
    
    patterns = [
        r"Check for any stale entries in the conntrack map",
        r"Done cleanup of conntrack map",
        r"Conntrack cleanup Delete",
        r"hydrated local conntrack cache",
        # Fallbacks...
    ]
```

## Cleanup Cycle Timing

### Controlled By
The cleanup period is controlled by the NPA configuration flag:
```
--conntrack-cache-cleanup-period=300
```
Default: 300 seconds (5 minutes)

### Detection Strategy
1. **Parse logs** for cleanup start/end messages
2. **Calculate intervals** between consecutive cleanups
3. **Predict next cleanup** based on detected interval
4. **Fallback to config** if detection fails

## Example Log Output

```
2024-12-04 20:00:00 [INFO] Check for any stale entries in the conntrack map
2024-12-04 20:00:01 [INFO] hydrated local conntrack cache
2024-12-04 20:00:01 [INFO] Done cleanup of conntrack map
...
2024-12-04 20:05:00 [INFO] Check for any stale entries in the conntrack map
2024-12-04 20:05:02 [INFO] Conntrack cleanup Delete - Conntrack Key : Source IP - 10.0.1.5 ...
2024-12-04 20:05:02 [INFO] Conntrack cleanup Delete - Conntrack Key : Source IP - 10.0.1.8 ...
2024-12-04 20:05:03 [INFO] Done cleanup of conntrack map
```

## Why Detection Might Fail

### Common Reasons

1. **No Recent Cleanup**
   - Script checks last 10 minutes only
   - If cleanup period is 300s, may need to wait

2. **Log Level Configuration**
   - NPA might be configured to not log INFO level
   - Check with: `kubectl logs -n kube-system -l k8s-app=aws-node`

3. **NPA Not Running**
   - Verify: `kubectl get pods -n kube-system -l k8s-app=aws-node`

4. **Different Label**
   - Some deployments use different labels
   - Check: `kubectl get pods -n kube-system | grep -E 'aws|node|network'`

## Verification

To verify the script can now detect cleanups:

```bash
# Check if NPA logs contain cleanup messages
kubectl logs -n kube-system -l k8s-app=aws-node --tail=500 | grep -E "Check for any stale|Done cleanup|Conntrack cleanup"

# Run the test
python3 conntrack_race_reproducer.py -v
```

If detection succeeds, you'll see:
```
[INFO] Detecting NPA cleanup cycle timing...
[INFO] Detected cleanup interval: ~300s
```

If it fails, you'll see:
```
[WARNING] Could not detect cleanup cycle from logs, will use configured period
```
This is **normal and OK** - the script will use fallback timing estimation.

## The Proposed Fix

### Consecutive Miss Approach

Instead of deleting on first miss, require 2 consecutive misses:

```python
# Maintain two sets
missing_entries_even_cycle = set()
missing_entries_odd_cycle = set()
is_even_cycle = True

# Every cleanup cycle
if is_even_cycle:
    for entry in local_cache:
        if entry not in kernel_cache:
            if entry in missing_entries_odd_cycle:
                delete_from_ebpf(entry)  # Missing 2x → delete
            else:
                missing_entries_even_cycle.add(entry)  # Track
    missing_entries_odd_cycle.clear()
    is_even_cycle = False
else:
    # Similar for odd cycle...
```

This ensures that entries must be missing from kernel for **2 full cleanup cycles** before deletion, virtually eliminating the race.

## References

- AWS Network Policy Agent: https://github.com/aws/aws-network-policy-agent
- Conntrack Client: `pkg/ebpf/conntrack/conntrack_client.go`
- Cleanup Functions: `CleanupConntrackMap()` and `Cleanupv6ConntrackMap()`
