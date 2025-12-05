# Kernel Conntrack Timeout Setup Guide

This guide explains how to set up the kernel conntrack timeout for reproducing the race condition.

## Why Kernel Timeout Matters

The race condition **requires** entries to be:
1. ✅ Present in NPA local cache
2. ✅ **Missing from kernel conntrack** ← This is critical!
3. ✅ Cleanup detects the mismatch
4. ✅ New connection reuses the same 5-tuple during cleanup

Without kernel expiry, entries remain in both kernel and cache, so cleanup won't try to delete them.

## Setup Steps

### Step 1: Deploy the Conntrack Tuner

This DaemonSet runs on all nodes and sets the kernel timeout to 30 seconds.

```bash
# Apply the tuner DaemonSet
kubectl apply -f k8s_conntrack_tuner.yaml

# Wait for pods to be ready (one per node)
kubectl wait --for=condition=ready pod -l app=conntrack-tuner -n kube-system --timeout=60s

# Verify it's running
kubectl get pods -n kube-system -l app=conntrack-tuner
```

Expected output:
```
NAME                     READY   STATUS    RESTARTS   AGE
conntrack-tuner-abc12    1/1     Running   0          10s
conntrack-tuner-def34    1/1     Running   0          10s
```

### Step 2: Verify the Timeout Was Set

Check the logs to confirm:

```bash
# Check logs from one of the tuner pods
kubectl logs -n kube-system -l app=conntrack-tuner --tail=20
```

You should see:
```
========================================
Conntrack Timeout Tuner Starting
========================================

Current TCP established timeout:
180
seconds

Setting TCP established timeout to 30 seconds...
New timeout: 30 seconds

✓ Successfully set conntrack timeout to 30 seconds

========================================
Configuration complete on ip-10-0-1-234
========================================

Keeping pod running... (delete DaemonSet to stop)
```

### Step 3: Run Your Test

Now the test will work correctly:

```bash
# The kernel will expire connections after 30 seconds
# So the test can create the race condition

python3 conntrack_race_reproducer.py
```

### Step 4: Clean Up After Testing

**IMPORTANT:** Reset the kernel timeout when done!

```bash
# Step 4a: Delete the tuner DaemonSet
kubectl delete -f k8s_conntrack_tuner.yaml

# Step 4b: Apply the reset DaemonSet
kubectl apply -f k8s_conntrack_reset.yaml

# Step 4c: Wait for reset to complete
kubectl wait --for=condition=complete job -l app=conntrack-reset -n kube-system --timeout=60s

# Step 4d: Verify reset
kubectl logs -n kube-system -l app=conntrack-reset --tail=20

# Step 4e: Delete the reset DaemonSet
kubectl delete -f k8s_conntrack_reset.yaml
```

## Troubleshooting

### Issue: Permission Denied

**Symptom:**
```
Error: pods is forbidden: User "..." cannot create resource "pods"
```

**Solution:**
You need cluster-admin or sufficient RBAC permissions to create privileged DaemonSets in kube-system.

```bash
# Check your permissions
kubectl auth can-i create daemonsets -n kube-system
kubectl auth can-i create pods/exec -n kube-system

# If "no", ask your cluster admin for permissions or use their account
```

### Issue: Pods Not Starting

**Symptom:**
```
NAME                     READY   STATUS              RESTARTS   AGE
conntrack-tuner-abc12    0/1     ContainerCreating   0          30s
```

**Solution:**
Check pod events:

```bash
kubectl describe pod -n kube-system -l app=conntrack-tuner
```

Common issues:
- Image pull failures (check network connectivity)
- SecurityContext denied (cluster policy restrictions)
- No nodes match toleration (check node taints)

### Issue: Conntrack Module Not Loaded

**Symptom in logs:**
```
ERROR: Conntrack module not loaded
```

**Solution:**
This means netfilter/conntrack isn't loaded on your nodes. This is rare, but if it happens:

1. Check if conntrack is actually needed in your cluster
2. The module might load automatically when needed
3. Or your kernel might not have netfilter compiled in (very rare)

### Issue: Timeout Not Changing

**Symptom in logs:**
```
✗ Failed to set conntrack timeout
```

**Solution:**

Check if the file is read-only or protected:

```bash
# Exec into tuner pod
kubectl exec -it -n kube-system <tuner-pod-name> -- sh

# Try manually
echo 30 > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established
cat /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established
```

## Security Considerations

### What This DaemonSet Does

- ✅ Runs with `privileged: true` security context
- ✅ Uses `hostNetwork` and `hostPID`
- ✅ Modifies kernel parameters on all nodes
- ✅ Uses minimal resources (10m CPU, 16Mi memory)

### Security Best Practices

1. **Only run in test/dev clusters**: Don't run this in production
2. **Time-limited**: Delete the DaemonSet after testing
3. **Always reset**: Use the reset DaemonSet to restore defaults
4. **Audit**: This creates audit logs showing privileged access

### Impact on Cluster

**While the tuner is running:**
- All TCP connections will expire after 30 seconds of inactivity
- This affects **all pods and services** on affected nodes
- Long-running idle connections may drop
- Reconnection attempts should work normally

**Why 30 seconds is safe for testing:**
- Most applications reconnect automatically
- Test pods are isolated in their own namespace
- Duration is short (only during active testing)
- Easy to reset back to normal

## Advanced: Custom Timeout Values

To use a different timeout value:

```bash
# Edit k8s_conntrack_tuner.yaml
# Change line: echo 30 > /proc/sys/net/netfilter/...
# To: echo 60 > /proc/sys/net/netfilter/...

# Then update test_config.yaml:
kernel_timeout: 60
cleanup_period: 120  # Should be > kernel_timeout
```

## Verification Commands

```bash
# Check if tuner is running
kubectl get ds conntrack-tuner -n kube-system

# View logs from all tuner pods
kubectl logs -n kube-system -l app=conntrack-tuner --tail=10 --all-containers=true

# Check how many nodes have the tuner
kubectl get pods -n kube-system -l app=conntrack-tuner -o wide

# Verify timeout on a specific node
kubectl exec -it -n kube-system <tuner-pod-name> -- cat /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established
```

## Complete Test Workflow

```bash
# 1. Deploy test resources
kubectl apply -f k8s_test_pods.yaml

# 2. Set kernel timeout
kubectl apply -f k8s_conntrack_tuner.yaml
kubectl wait --for=condition=ready pod -l app=conntrack-tuner -n kube-system --timeout=60s

# 3. Verify timeout is set
kubectl logs -n kube-system -l app=conntrack-tuner --tail=5

# 4. Run the test
python3 conntrack_race_reproducer.py

# 5. Clean up test pods
kubectl delete -f k8s_test_pods.yaml

# 6. Reset kernel timeout
kubectl delete -f k8s_conntrack_tuner.yaml
kubectl apply -f k8s_conntrack_reset.yaml
kubectl wait --for=condition=ready pod -l app=conntrack-reset -n kube-system --timeout=60s
kubectl delete -f k8s_conntrack_reset.yaml
```

## Quick Reference

| File | Purpose | When to Use |
|------|---------|-------------|
| `k8s_conntrack_tuner.yaml` | Sets timeout to 30s | Before testing |
| `k8s_conntrack_reset.yaml` | Resets timeout to 180s | After testing |
| `test_config.yaml` | Configure test parameters | Adjust for your timing |

## Questions?

- **How long to keep tuner running?** Only during active testing (minutes to hours)
- **Does it affect production?** Yes! Only use in dev/test clusters
- **Can I use different timeout?** Yes, edit the YAML files
- **What if I forget to reset?** Cluster will function normally but connections expire faster
- **Is this reversible?** Yes, 100% reversible with reset DaemonSet

## Summary

1. ✅ Deploy `k8s_conntrack_tuner.yaml` → Sets 30s timeout
2. ✅ Run `conntrack_race_reproducer.py` → Tests the race
3. ✅ Deploy `k8s_conntrack_reset.yaml` → Resets to 180s
4. ✅ Clean up both DaemonSets → Back to normal

The kernel timeout is **essential** for reproducing the race condition - this setup makes it easy and safe!
