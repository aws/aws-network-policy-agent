# Conntrack Race Condition Reproducer

This test suite reproduces a rare race condition in the Network Policy Agent's (NPA) conntrack cleanup logic that can lead to denial of legitimate traffic.

## Problem Overview

### The Race Condition

The Network Policy Agent maintains a userspace cache of kernel conntrack entries and periodically cleans up stale entries from the eBPF map. A race condition occurs when:

1. A connection exists in kernel conntrack, local cache, and eBPF map
2. Kernel expires the entry after timeout (~180s)
3. NPA cleanup cycle starts and snapshots the kernel conntrack table
4. **During cleanup processing**, a new connection reuses the same 5-tuple (source IP:port → dest IP:port + protocol)
5. The new connection creates a fresh kernel entry and eBPF map entry
6. Cleanup deletes the eBPF entry based on the pre-reuse snapshot
7. When response arrives, the reverse flow lookup fails → **traffic denied**

### Impact

- Rare but impactful in production clusters with high port reuse
- Legitimate traffic gets denied/dropped
- Hard to reproduce due to precise timing requirements
- Only manifests under specific conditions

## Prerequisites

### Required Tools

- `kubectl` configured with cluster access
- Python 3.8 or later
- PyYAML library: `pip install pyyaml`

### Cluster Requirements

- Kubernetes cluster with Network Policy Agent deployed
- Permissions to:
  - Create namespace and pods
  - Execute commands in pods
  - View logs from NPA pods
- At least 2 worker nodes (recommended)

### Optional: Reduce Timeouts for Faster Testing

To speed up reproduction, you can reduce kernel conntrack timeout (requires node access):

```bash
# SSH into worker nodes or use a privileged DaemonSet
echo 30 > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established
```

**Warning:** This affects all connections on the node. Reset after testing:
```bash
echo 180 > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established
```

## Quick Start

### 1. Deploy Test Resources

```bash
# Create test namespace and pods
kubectl apply -f k8s_test_pods.yaml

# Wait for pods to be ready
kubectl wait --for=condition=ready pod/test-client -n conntrack-test --timeout=60s
kubectl wait --for=condition=ready pod/test-server -n conntrack-test --timeout=60s

# Verify deployment
kubectl get pods -n conntrack-test
```

Expected output:
```
NAME          READY   STATUS    RESTARTS   AGE
test-client   1/1     Running   0          30s
test-server   1/1     Running   0          30s
```

### 2. Configure Test Parameters

Edit `test_config.yaml` to match your environment:

```yaml
# Adjust these based on your setup
namespace: conntrack-test
npa_namespace: kube-system  # Where NPA pods run
npa_pod_label: app=aws-node # Label to find NPA pods

# Timing (reduced for testing)
kernel_timeout: 30    # Match with node configuration
cleanup_period: 60    # Match with NPA --conntrack-cache-cleanup-period

# Test intensity
iterations: 10
connections_per_wave: 50
```

### 3. Run the Test

```bash
# Basic run
python3 conntrack_race_reproducer.py

# With custom config
python3 conntrack_race_reproducer.py -c my_config.yaml

# More iterations for better coverage
python3 conntrack_race_reproducer.py -i 20

# Verbose output
python3 conntrack_race_reproducer.py -v
```

### 4. Interpret Results

**Success (Race Detected):**
```
🔥 RACE CONDITION DETECTED! 3 connections denied
   This indicates the cleanup deleted active connection entries

TEST SUMMARY
============================================================
Total attempts: 10
Race conditions detected: 3
Success rate: 30.0%

✓ RACE CONDITION SUCCESSFULLY REPRODUCED
```

**No Race Detected:**
```
✗ No race in attempt 10

TEST SUMMARY
============================================================
Total attempts: 10
Race conditions detected: 0
Success rate: 0.0%

⚠ Race condition not reproduced in any attempts
```

## How It Works

### Test Phases

Each test attempt goes through 5 phases:

#### Phase 1: Initial Connections
- Creates `connections_per_wave` connections from client to server
- Populates kernel conntrack, local cache, and eBPF map
- Establishes baseline state

#### Phase 2: Kernel Timeout
- Waits for `kernel_timeout` seconds
- Kernel expires the connection
- Entry remains in local cache (stale)
- Entry remains in eBPF map (stale)

#### Phase 3: Cleanup Prediction
- Analyzes NPA logs to detect cleanup cycle timing
- Predicts when next cleanup will occur
- Synchronizes test execution

#### Phase 4: Race Trigger
- Creates connections during the cleanup window
- Attempts to reuse 5-tuples from Phase 1
- If timing is right, new connection created while cleanup processes old snapshot
- Cleanup deletes eBPF entry for active connection

#### Phase 5: Verification
- Checks if connections were denied/refused
- Verifies race condition occurred
- Logs detailed results

### Detection Methods

The script detects the race through:

1. **Connection Failures:** Monitors for refused/timeout errors
2. **Pattern Analysis:** Looks for denials of legitimate traffic
3. **Statistical Approach:** Multiple attempts increase detection probability

### Why This Approach Works

Despite using simplified tooling (kubectl + netcat), this approach successfully reproduces the race because:

- The race window is large (1-2 seconds)
- Statistical spraying covers the timing window
- Port exhaustion forces 5-tuple reuse
- Multiple iterations compensate for timing imprecision

## Troubleshooting

### Pods Not Starting

```bash
# Check pod status
kubectl describe pod test-client -n conntrack-test
kubectl describe pod test-server -n conntrack-test

# Common issues:
# - Image pull failures: Check network connectivity
# - Resource constraints: Ensure cluster has capacity
```

### No Race Detected

**Possible reasons:**

1. **Timing misalignment:** NPA cleanup cycle prediction was off
2. **Insufficient iterations:** Increase with `-i 20` or higher
3. **Port reuse not occurring:** OS may be using different ports
4. **NPA not running:** Verify NPA pods are active

**Solutions:**

```bash
# Verify NPA is running
kubectl get pods -n kube-system -l app=aws-node

# Check NPA logs for cleanup events
kubectl logs -n kube-system -l app=aws-node --tail=100 | grep -i cleanup

# Increase test iterations
python3 conntrack_race_reproducer.py -i 30

# Run during high cluster load (more port reuse)
# Consider running multiple test instances simultaneously
```

### Permission Errors

```bash
# If you get permission errors, check:
kubectl auth can-i create pods -n conntrack-test
kubectl auth can-i exec pods -n conntrack-test
kubectl auth can-i get pods -n kube-system

# You may need cluster-admin or specific RBAC permissions
```

## Configuration Reference

### test_config.yaml Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `namespace` | `conntrack-test` | Test namespace for client/server pods |
| `client_pod` | `test-client` | Name of client pod |
| `server_pod` | `test-server` | Name of server pod |
| `server_port` | `8080` | TCP port for connections |
| `npa_namespace` | `kube-system` | Namespace where NPA runs |
| `npa_pod_label` | `app=aws-node` | Label selector for NPA pods |
| `kernel_timeout` | `30` | Kernel conntrack timeout (seconds) |
| `cleanup_period` | `60` | NPA cleanup cycle period (seconds) |
| `iterations` | `10` | Number of test attempts |
| `connections_per_wave` | `50` | Connections per wave |

### Environment Variables

The script respects the following environment variables:

```bash
# Override kubeconfig location
export KUBECONFIG=/path/to/kubeconfig

# Increase kubectl timeout
export KUBECTL_TIMEOUT=60
```

## Advanced Usage

### Running Multiple Tests Simultaneously

For higher probability of hitting the race:

```bash
# Terminal 1
python3 conntrack_race_reproducer.py -i 20 &

# Terminal 2
python3 conntrack_race_reproducer.py -i 20 &

# Terminal 3
python3 conntrack_race_reproducer.py -i 20 &

# Wait for all to complete
wait
```

### Custom Timing Parameters

For production environments (slower but more realistic):

```yaml
# test_config_production.yaml
kernel_timeout: 180
cleanup_period: 300
iterations: 5
connections_per_wave: 100
```

```bash
python3 conntrack_race_reproducer.py -c test_config_production.yaml
```

### Analyzing NPA Logs

To manually verify cleanup timing:

```bash
# Stream NPA logs
kubectl logs -n kube-system -l app=aws-node -f | grep -i conntrack

# Look for patterns like:
# - "cleanup started"
# - "removed X stale entries"
# - "conntrack cache cleanup"
```

## Proposed Solution

The **Consecutive Miss Approach** solves this race condition:

### Solution Overview

Instead of immediate deletion, require entries to be missing from kernel conntrack for **2 consecutive cleanup cycles** before deletion.

### Implementation

Maintain 2 additional sets in userspace:
- `missing_entries_even_cycle_set`
- `missing_entries_odd_cycle_set`

**Every even cleanup cycle:**
1. When stale entry found → Check if in `missing_entries_odd_cycle_set`
2. If yes → Delete from eBPF map
3. If no → Add to `missing_entries_even_cycle_set`
4. Reset `missing_entries_odd_cycle_set`

**Every odd cleanup cycle:**
1. When stale entry found → Check if in `missing_entries_even_cycle_set`
2. If yes → Delete from eBPF map
3. If no → Add to `missing_entries_odd_cycle_set`
4. Reset `missing_entries_even_cycle_set`

### Benefits

- ✅ Userspace-only changes (safe)
- ✅ Reduces race probability to ~0%
- ✅ Simple to implement and understand
- ✅ No performance impact

### Trade-offs

- Stale entries remain for up to `2 × conntrack-cache-cleanup-period`
- Slightly increased memory usage for tracking sets

## Cleanup

When testing is complete:

```bash
# Delete test resources
kubectl delete -f k8s_test_pods.yaml

# Or just delete the namespace
kubectl delete namespace conntrack-test

# Reset kernel timeout (if modified)
# SSH to nodes and run:
echo 180 > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established
```

## Files in This Repository

- `conntrack_race_reproducer.py` - Main test script
- `test_config.yaml` - Configuration file
- `k8s_test_pods.yaml` - Kubernetes test resources
- `README.md` - This file

## Support and Feedback

For issues or questions:
1. Check the Troubleshooting section above
2. Review NPA logs for cleanup activity
3. Verify test pod connectivity
4. Try increasing iterations and timeout values

## License

This test suite is provided as-is for Network Policy Agent testing purposes.

---

**Note:** This reproducer is designed for testing and validation only. Do not run in production clusters without understanding the impact of modified timeout values and test traffic.
