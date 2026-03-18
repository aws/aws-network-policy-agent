# Troubleshooting Guide

## Server Connection Refused Error

If you see errors like:
```
nc: connect to 192.168.72.235 port 8080 (tcp) failed: Connection refused
```

### Quick Fix

The server pod needs time to start listening. Try these steps:

#### 1. Check if pods are running
```bash
kubectl get pods -n conntrack-test
```

Expected output:
```
NAME          READY   STATUS    RESTARTS   AGE
test-client   1/1     Running   0          2m
test-server   1/1     Running   0          2m
```

#### 2. Check server logs
```bash
kubectl logs test-server -n conntrack-test
```

You should see:
```
Starting TCP server on port 8080...
```

#### 3. Manually test connectivity
```bash
# Get server IP
SERVER_IP=$(kubectl get pod test-server -n conntrack-test -o jsonpath='{.status.podIP}')
echo "Server IP: $SERVER_IP"

# Test from client pod
kubectl exec -n conntrack-test test-client -- nc -zv $SERVER_IP 8080
```

#### 4. If server isn't listening, restart it
```bash
# Delete and recreate pods
kubectl delete pod test-server -n conntrack-test
kubectl wait --for=condition=ready pod/test-server -n conntrack-test --timeout=60s

# Wait a few seconds for server to start listening
sleep 5

# Test again
python3 conntrack_race_reproducer.py
```

### Alternative: Use a Different Server Image

If netcat issues persist, you can modify `k8s_test_pods.yaml` to use Python's built-in HTTP server:

```yaml
  - name: server
    image: python:3.9-slim
    command:
    - /bin/sh
    - -c
    - |
      cat > /tmp/server.py << 'EOF'
      import socket
      import time
      
      HOST = '0.0.0.0'
      PORT = 8080
      
      with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
          s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
          s.bind((HOST, PORT))
          s.listen()
          print(f'Server listening on {HOST}:{PORT}')
          
          while True:
              conn, addr = s.accept()
              with conn:
                  print(f'Connected by {addr}')
                  data = conn.recv(1024)
                  if data:
                      conn.sendall(data)
      EOF
      
      python3 /tmp/server.py
```

Then redeploy:
```bash
kubectl delete -f k8s_test_pods.yaml
kubectl apply -f k8s_test_pods.yaml
kubectl wait --for=condition=ready pod --all -n conntrack-test --timeout=60s
sleep 5  # Give server time to start
python3 conntrack_race_reproducer.py
```

## Common Issues

### Issue: Pods not starting

**Check events:**
```bash
kubectl describe pod test-server -n conntrack-test
kubectl describe pod test-client -n conntrack-test
```

**Common causes:**
- Image pull failures (check network/registry access)
- Resource constraints (check cluster capacity)
- ImagePullBackOff (check image availability)

**Solution:**
```bash
# Try using a different base image
# Edit k8s_test_pods.yaml and change:
# image: nicolaka/netshoot:latest
# to:
# image: busybox:latest
```

### Issue: Server listening but connections fail

**Check if server is actually listening:**
```bash
kubectl exec -n conntrack-test test-server -- netstat -tlnp 2>/dev/null || \
kubectl exec -n conntrack-test test-server -- ss -tlnp
```

**Check iptables/network policies:**
```bash
# List network policies
kubectl get networkpolicies -n conntrack-test

# If policies are blocking, delete them temporarily
kubectl delete networkpolicy --all -n conntrack-test
```

### Issue: Permission errors

**Check RBAC permissions:**
```bash
kubectl auth can-i create pods -n conntrack-test
kubectl auth can-i exec pods -n conntrack-test
kubectl auth can-i get pods -n kube-system
```

**If permissions denied, ask cluster admin for:**
- Pod creation in conntrack-test namespace
- Pod exec in conntrack-test namespace
- View logs from kube-system namespace

### Issue: NPA not found

**Check NPA deployment:**
```bash
# List all pods in kube-system
kubectl get pods -n kube-system

# Look for NPA pods (common names: aws-node, calico, cilium)
kubectl get pods -n kube-system | grep -E 'aws-node|calico|cilium'
```

**Update config if NPA has different label:**
```yaml
# In test_config.yaml
npa_namespace: kube-system
npa_pod_label: app=your-npa-label  # Change this
```

### Issue: Race never detected

**This is actually somewhat normal!** The race is timing-sensitive.

**Try these:**

1. **More iterations:**
   ```bash
   python3 conntrack_race_reproducer.py -i 30
   ```

2. **Run multiple instances:**
   ```bash
   for i in {1..5}; do 
     python3 conntrack_race_reproducer.py -i 10 & 
   done
   wait
   ```

3. **Adjust timing in config:**
   ```yaml
   # Make timing match your environment
   kernel_timeout: 30      # Actual kernel timeout
   cleanup_period: 60      # Actual NPA cleanup period
   connections_per_wave: 100  # More connections
   ```

4. **Run during high load** (more port reuse)

5. **Reduce kernel timeout on nodes** (faster testing):
   ```bash
   # SSH to nodes or use privileged DaemonSet
   echo 30 > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established
   ```

## Debug Mode

Run with verbose logging:
```bash
python3 conntrack_race_reproducer.py -v
```

This shows detailed command output and timing information.

## Manual Test

Test connectivity manually:
```bash
# Terminal 1: Watch server logs
kubectl logs -f test-server -n conntrack-test

# Terminal 2: Create connections
SERVER_IP=$(kubectl get pod test-server -n conntrack-test -o jsonpath='{.status.podIP}')

for i in {1..10}; do
  echo "Connection $i" | kubectl exec -n conntrack-test test-client -- nc -v $SERVER_IP 8080
  sleep 0.5
done
```

## Clean Start

If all else fails, start fresh:
```bash
# Delete everything
kubectl delete namespace conntrack-test
kubectl delete -f k8s_test_pods.yaml

# Wait for cleanup
sleep 10

# Redeploy
kubectl apply -f k8s_test_pods.yaml

# Wait for ready
kubectl wait --for=condition=ready pod --all -n conntrack-test --timeout=120s

# Give extra time for server
sleep 10

# Verify manually
SERVER_IP=$(kubectl get pod test-server -n conntrack-test -o jsonpath='{.status.podIP}')
kubectl exec -n conntrack-test test-client -- nc -zv $SERVER_IP 8080

# If successful, run test
python3 conntrack_race_reproducer.py
```

## Getting Help

If issues persist, gather this information:

```bash
# Environment info
kubectl version
kubectl get nodes
kubectl get pods -n conntrack-test -o wide

# Pod details
kubectl describe pod test-server -n conntrack-test
kubectl describe pod test-client -n conntrack-test

# Pod logs
kubectl logs test-server -n conntrack-test
kubectl logs test-client -n conntrack-test

# Network info
kubectl get svc -n conntrack-test
kubectl get networkpolicies -n conntrack-test
```

Share these details when asking for help.
