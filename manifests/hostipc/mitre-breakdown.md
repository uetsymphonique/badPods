# MITRE ATT&CK Mapping: HostIPC Pod

## Attack Flow

```
Initial Access → Execution → Discovery → Collection
```

---

## MITRE ATT&CK Techniques

### 1. Initial Access

#### T1078 - Valid Accounts
**Behavior:** Attacker uses compromised Kubernetes credentials

**Procedures:**
```bash
kubectl apply -f hostipc-exec-pod.yaml
```

---

### 2. Execution

#### T1609 - Container Administration Command
**Behavior:** Execute commands in container via kubectl exec

**Procedures:**
```bash
kubectl exec -it hostipc-exec-pod -- bash
```

#### T1059.004 - Command and Scripting Interpreter: Unix Shell
**Behavior:** Execute bash commands to access shared memory and IPC mechanisms

**Procedures:**
```bash
ls -al /dev/shm/
cat /dev/shm/secretfile.txt
ipcs -a
```

---

### 3. Discovery

#### T1082 - System Information Discovery
**Behavior:** Enumerate inter-process communication facilities

**Procedures:**
```bash
ipcs -a
ipcs -m  # Shared memory
ipcs -s  # Semaphore arrays
ipcs -q  # Message queues
```

---

### 4. Collection

#### T1005 - Data from Local System
**Behavior:** Access files in shared memory (/dev/shm)

**Procedures:**
```bash
ls -al /dev/shm/
cat /dev/shm/secretpassword.txt
```

#### T1056.001 - Input Capture: Keylogging
**Behavior:** Potentially intercept IPC communications (shared memory, message queues)

**Procedures:**
```bash
# Monitor shared memory
watch -n 1 'ls -al /dev/shm/'

# Read IPC message queues if accessible
ipcrm -q [ID]
```

---

## Technique Summary

| Tactic | Technique ID | Technique Name |
|--------|-------------|----------------|
| Initial Access | T1078 | Valid Accounts |
| Execution | T1609 | Container Administration Command |
| Execution | T1059.004 | Unix Shell |
| Discovery | T1082 | System Information Discovery |
| Collection | T1005 | Data from Local System |
| Collection | T1056.001 | Input Capture |

**Total: 6 Techniques across 4 Tactics**

**Pod Configuration:**
```yaml
spec:
  hostIPC: true
```

**Key Features:**
- Access to /dev/shm shared between host and pods
- Can read/write to host IPC mechanisms
- Shared memory, semaphore arrays, message queues
- Limited exploitation potential unless IPC is actively used
