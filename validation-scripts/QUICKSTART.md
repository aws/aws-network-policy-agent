# Quick Start Guide

## TL;DR - Get Running in 5 Minutes

```bash
# 1. Run setup (validates prerequisites)
./setup.sh

# 2. Deploy test pods
kubectl apply -f k8s_test_pods.yaml

# 3. Set kernel timeout (REQUIRED for race reproduction)
kubectl apply -f k8s_conntrack_tuner.yaml
kubectl wait --for=condition=ready pod -l app=conntrack-tuner -n kube-system --timeout=60s

# 4. Wait for pods ready
kubectl wait --for=condition=ready pod --all -n conntrack-test --timeout=60s

# 5. Run the test
python3 conntrack_race_reproducer.py

# 6. Clean up kernel timeout (IMPORTANT!)
kubectl delete -f k8s_conntrack_tuner.yaml
kubectl apply -f k8s_conntrack_reset.yaml
kubectl wait --for=condition=ready pod -l app=conntrack-reset -n kube-system --timeout=60s
kubectl delete -f k8s_conntrack_reset.yaml
```

## What This Does

Reproduces a race condition where:
- Kernel expires a connection after 30 seconds (via tuner)
- NPA cleanup snapshots conntrack (missing the expired entry)
- **NEW connection reuses same 5-tuple during cleanup**
- Cleanup deletes eBPF entry for the NEW connection
- Response packets get denied → **RACE TRIGGERED**

**⚠️ IMPORTANT:** The kernel timeout tuner is **required** - without it, entries won't expire and the race won't occur!

## Expected Output

### Success
```
🔥 RACE CONDITION DETECTED! 3 connections denied
```

### No Race (Try More Iterations)
```
python3 conntrack_race_reproducer.py -i 20
```

## Configuration

Edit `test_config.yaml` before running:

```yaml
# Match your cluster
npa_namespace: kube-system
npa_pod_label: app=aws-node

# For faster testing (requires node access)
kernel_timeout: 30
cleanup_period: 60
```

## Key Parameters

| Flag | Purpose | Example |
|------|---------|---------|
| `-i` | More iterations | `python3 conntrack_race_reproducer.py -i 30` |
| `-c` | Custom config | `python3 conntrack_race_reproducer.py -c prod_config.yaml` |
| `-v` | Verbose output | `python3 conntrack_race_reproducer.py -v` |

## Troubleshooting

### No race detected?
```bash
# Try more iterations
python3 conntrack_race_reproducer.py -i 30

# Check NPA is running
kubectl get pods -n kube-system -l app=aws-node

# Run multiple instances (increases probability)
for i in {1..3}; do python3 conntrack_race_reproducer.py -i 10 & done
wait
```

### Pods not starting?
```bash
kubectl describe pod test-client -n conntrack-test
kubectl describe pod test-server -n conntrack-test
```

### Permission errors?
```bash
kubectl auth can-i create pods -n conntrack-test
kubectl auth can-i exec pods -n conntrack-test
```

## Clean Up

```bash
kubectl delete -f k8s_test_pods.yaml
```

## How It Works (5 Phases)

1. **Initial Connections** → Populate tables
2. **Kernel Timeout** → Wait for expiry
3. **Cleanup Prediction** → Sync with NPA cycle
4. **Race Trigger** → Spray connections during cleanup
5. **Verification** → Check for denials

## The Fix (Consecutive Miss Approach)

Require 2 consecutive cleanup cycles to miss an entry before deletion:
- Even cycle: Check odd set → delete or add to even set
- Odd cycle: Check even set → delete or add to odd set

**Result:** Race probability → ~0%

## Files Reference

- `conntrack_race_reproducer.py` - Main test script
- `test_config.yaml` - Configuration
- `k8s_test_pods.yaml` - Test pods
- `setup.sh` - Prerequisites checker
- `README.md` - Full documentation
- `QUICKSTART.md` - This file

---

For detailed information, see [README.md](README.md)
