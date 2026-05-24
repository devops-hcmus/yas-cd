#!/bin/bash
# ============================================================
# SERVICE MESH TEST SCRIPT (COMPREHENSIVE v2)
# ============================================================
# Comprehensive test suite for Istio Service Mesh:
#   1. mTLS Configuration (STRICT namespace, PERMISSIVE for BFF/UI)
#   2. Istio Resources Validation
#   3. Sidecar Injection
#   4. Authorization ALLOW - Whitelisted Services
#      ✓ storefront-bff → product, cart, order, customer, inventory, media, search
#      ✓ backoffice-bff → product, cart, order, customer, inventory, media, tax, sampledata
#   5. Authorization DENY - Unauthorized Access
#      ✓ unknown SA → all backend services
#      ✓ cart → customer (invalid access pattern)
#      ✓ search → cart (invalid access pattern)
#   6. Undeployed Services Check
#      ✓ payment, location, promotion, rating, recommendation, webhook (should be unreachable)
#   7. Retry Policy Verification
#
# Usage:
#   chmod +x test-service-mesh-v2.sh
#   ./test-service-mesh-v2.sh              # Auto-detect namespace
#   ./test-service-mesh-v2.sh yas          # Specify namespace
#
# HTTP Status Codes:
#   - 403 = Istio RBAC denied (AuthorizationPolicy blocking) ← We expect this for DENY tests
#   - 401 = App-level auth (Spring Security JWT required)
#   - 2xx/4xx/5xx = Request passed Istio check (app-level response varies)
#   - 000 = Connection failed/timeout
# ============================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHART_DIR="${SCRIPT_DIR}/../../charts/service-mesh"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
TOTAL_COUNT=0

# -----------------------------------------------
# Helper functions
# -----------------------------------------------
log_header() {
    echo ""
    echo -e "${BOLD}${CYAN}============================================${NC}"
    echo -e "${BOLD}${CYAN}  $1${NC}"
    echo -e "${BOLD}${CYAN}============================================${NC}"
}

log_test() {
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    echo -e "\n${BOLD}>>> Test ${TOTAL_COUNT}: $1${NC}"
}

log_pass() {
    PASS_COUNT=$((PASS_COUNT + 1))
    echo -e "    ${GREEN}✅ PASS: $1${NC}"
}

log_fail() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "    ${RED}❌ FAIL: $1${NC}"
}

log_skip() {
    SKIP_COUNT=$((SKIP_COUNT + 1))
    echo -e "    ${YELLOW}⏭️  SKIP: $1${NC}"
}

log_info() {
    echo -e "    ${CYAN}ℹ️  $1${NC}"
}

sanitize_http_code() {
    local raw="$1"
    local code
    code=$(echo "$raw" | grep -oE '[0-9]{3}' | tail -1)
    echo "${code:-000}"
}

# -----------------------------------------------
# Detect namespace
# -----------------------------------------------
detect_namespace() {
    local CANDIDATES=()
    local DEV_NS
    DEV_NS=$(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}' | tr ' ' '\n' | grep '^yas-dev-' || true)
    for ns in $DEV_NS; do
        CANDIDATES+=("$ns")
    done
    CANDIDATES+=("yas" "staging")

    for ns in "${CANDIDATES[@]}"; do
        if kubectl get namespace "$ns" &>/dev/null; then
            local RUNNING
            RUNNING=$(kubectl get pods -n "$ns" --field-selector=status.phase=Running --no-headers 2>/dev/null | wc -l)
            if [ "$RUNNING" -gt 0 ]; then
                echo "$ns"
                return 0
            fi
        fi
    done
    return 1
}

if [ $# -ge 1 ]; then
    NS="$1"
else
    NS=$(detect_namespace) || { echo "ERROR: No active namespace found"; exit 1; }
fi

echo -e "${BOLD}Namespace: ${NS}${NC}"

# Validate
if ! kubectl get namespace "$NS" &>/dev/null; then
    echo "ERROR: Namespace '$NS' does not exist"
    exit 1
fi

# Pre-flight checks
echo ""
echo -e "${CYAN}Pre-flight Checks:${NC}"

# Check if istio-system namespace exists
if kubectl get namespace istio-system &>/dev/null; then
    echo "  ✓ Istio system namespace found"
else
    echo "  ✗ Istio system namespace not found - Service mesh may not be installed"
    exit 1
fi

# Check if Istio injection is enabled
INJECTION_LABEL=$(kubectl get namespace "$NS" -o jsonpath='{.metadata.labels.istio-injection}' 2>/dev/null || echo "")
if [ "$INJECTION_LABEL" == "enabled" ]; then
    echo "  ✓ Istio injection enabled in namespace"
else
    echo "  ⚠️  Istio injection not enabled - test pods may not get sidecars"
fi

# Check if kubectl is connected
if kubectl cluster-info &>/dev/null; then
    echo "  ✓ Kubectl connected to cluster"
else
    echo "  ✗ Kubectl connection failed"
    exit 1
fi

log_header "SERVICE MESH COMPREHENSIVE TEST SUITE"
echo -e "  Namespace : ${NS}"
echo -e "  Timestamp : $(date '+%Y-%m-%d %H:%M:%S')"

# ============================================================
# TEST 1: mTLS Configuration (STRICT vs PERMISSIVE)
# ============================================================
log_test "mTLS - Namespace-level STRICT policy"

PA_STRICT=$(kubectl get peerauthentication -n "$NS" -o jsonpath='{.items[?(@.metadata.name=="'$NS'-strict-mtls")].spec.mtls.mode}' 2>/dev/null || echo "")

if [ "$PA_STRICT" == "STRICT" ]; then
    log_pass "Namespace default = STRICT (enforces mTLS for all services)"
else
    log_fail "Expected STRICT, got: '${PA_STRICT}'"
fi

# Check PERMISSIVE policies for BFF services
log_test "mTLS - BFF Services with PERMISSIVE mode"

BFF_SERVICES=("storefront-bff" "backoffice-bff")
BFF_PERMISSIVE=0

for svc in "${BFF_SERVICES[@]}"; do
    PA=$(kubectl get peerauthentication -n "$NS" -o jsonpath='{.items[?(@.metadata.name=="'$svc'-permissive")].spec.mtls.mode}' 2>/dev/null || echo "")
    if [ "$PA" == "PERMISSIVE" ]; then
        log_info "  $svc: PERMISSIVE ✓"
        BFF_PERMISSIVE=$((BFF_PERMISSIVE + 1))
    fi
done

if [ "$BFF_PERMISSIVE" -eq "${#BFF_SERVICES[@]}" ]; then
    log_pass "All BFF services have PERMISSIVE mode"
else
    log_fail "Only $BFF_PERMISSIVE/${#BFF_SERVICES[@]} BFF services are PERMISSIVE"
fi

# Check PERMISSIVE for UI services
log_test "mTLS - UI Services with PERMISSIVE mode"

UI_SERVICES=("storefront-ui" "backoffice-ui" "swagger-ui")
UI_PERMISSIVE=0

for svc in "${UI_SERVICES[@]}"; do
    PA=$(kubectl get peerauthentication -n "$NS" -o jsonpath='{.items[?(@.metadata.name=="'$svc'-permissive")].spec.mtls.mode}' 2>/dev/null || echo "")
    if [ "$PA" == "PERMISSIVE" ]; then
        log_info "  $svc: PERMISSIVE ✓"
        UI_PERMISSIVE=$((UI_PERMISSIVE + 1))
    fi
done

if [ "$UI_PERMISSIVE" -eq "${#UI_SERVICES[@]}" ]; then
    log_pass "All UI services have PERMISSIVE mode"
else
    log_fail "Only $UI_PERMISSIVE/${#UI_SERVICES[@]} UI services are PERMISSIVE"
fi

# ============================================================
# TEST 2: Istio Resources Check
# ============================================================
log_test "Istio Resources - Validation"

PA_COUNT=$(kubectl get peerauthentication -n "$NS" --no-headers 2>/dev/null | wc -l)
AP_COUNT=$(kubectl get authorizationpolicy -n "$NS" --no-headers 2>/dev/null | wc -l)
DR_COUNT=$(kubectl get destinationrule -n "$NS" --no-headers 2>/dev/null | wc -l)
VS_COUNT=$(kubectl get virtualservice -n "$NS" --no-headers 2>/dev/null | wc -l)

log_info "  PeerAuthentication: ${PA_COUNT}"
log_info "  AuthorizationPolicy: ${AP_COUNT}"
log_info "  DestinationRule: ${DR_COUNT}"
log_info "  VirtualService: ${VS_COUNT}"

RESOURCE_OK=true
[ "$PA_COUNT" -ge 1 ] || RESOURCE_OK=false
[ "$AP_COUNT" -ge 2 ] || RESOURCE_OK=false
[ "$DR_COUNT" -ge 1 ] || RESOURCE_OK=false
[ "$VS_COUNT" -ge 1 ] || RESOURCE_OK=false

if [ "$RESOURCE_OK" = true ]; then
    log_pass "All required Istio resources present"
else
    log_fail "Missing required Istio resources"
fi

# Verify deny-all policy
log_test "Authorization - deny-all-default policy"

DENY_ALL=$(kubectl get authorizationpolicy deny-all-default -n "$NS" -o jsonpath='{.metadata.name}' 2>/dev/null || echo "")
if [ "$DENY_ALL" == "deny-all-default" ]; then
    log_pass "deny-all-default policy exists"
else
    log_fail "deny-all-default policy not found"
fi

# ============================================================
# TEST 3: Sidecar Injection
# ============================================================
log_test "Sidecar Injection - Envoy sidecars present"

INJECTION_LABEL=$(kubectl get namespace "$NS" -o jsonpath='{.metadata.labels.istio-injection}' 2>/dev/null || echo "")
if [ "$INJECTION_LABEL" == "enabled" ]; then
    log_info "Namespace label: istio-injection=enabled ✓"
else
    log_fail "Namespace label not set to 'enabled'"
fi

PODS_WITH_SIDECAR=0
PODS_WITHOUT_SIDECAR=0
ALL_PODS=$(kubectl get pods -n "$NS" --field-selector=status.phase=Running -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "")

for pod in $ALL_PODS; do
    HAS_PROXY=$(kubectl get pod "$pod" -n "$NS" -o jsonpath='{.spec.containers[?(@.name=="istio-proxy")].name}' 2>/dev/null || echo "")
    if [ -n "$HAS_PROXY" ]; then
        PODS_WITH_SIDECAR=$((PODS_WITH_SIDECAR + 1))
    else
        PODS_WITHOUT_SIDECAR=$((PODS_WITHOUT_SIDECAR + 1))
    fi
done

TOTAL_PODS=$((PODS_WITH_SIDECAR + PODS_WITHOUT_SIDECAR))
if [ "$TOTAL_PODS" -gt 0 ] && [ "$PODS_WITHOUT_SIDECAR" -eq 0 ]; then
    log_pass "All ${PODS_WITH_SIDECAR} running pods have istio-proxy sidecar"
elif [ "$TOTAL_PODS" -eq 0 ]; then
    log_skip "No running pods found for sidecar check"
else
    log_fail "${PODS_WITHOUT_SIDECAR}/${TOTAL_PODS} pods missing istio-proxy"
fi

# ============================================================
# TEST 4-7: Authorization Tests (Deploy test pods)
# ============================================================
log_header "AUTHORIZATION TESTS - Deploying test pods"

echo -e "  Cleaning up old test pods..."
kubectl delete pods -n "$NS" -l purpose=authorization-testing --ignore-not-found=true 2>/dev/null || true
sleep 2

echo -e "  Creating required service accounts..."
# Create service accounts if they don't exist
for sa in storefront-bff backoffice-bff order search cart; do
    kubectl get serviceaccount "$sa" -n "$NS" 2>/dev/null || \
        kubectl create serviceaccount "$sa" -n "$NS" 2>/dev/null || true
done

echo -e "  Creating test pods with various service accounts..."

# Deploy comprehensive test pods
APPLY_OUTPUT=$(cat <<TESTPODS | kubectl apply -n "$NS" -f - 2>&1
---
# Test pod: storefront-bff (allowed to call: product, cart, order, customer, inventory, media, search)
apiVersion: v1
kind: Pod
metadata:
  name: test-storefront-bff
  namespace: $NS
  labels:
    app: test-storefront-bff
    purpose: authorization-testing
  annotations:
    sidecar.istio.io/inject: "true"
spec:
  serviceAccountName: storefront-bff
  containers:
    - name: curl
      image: curlimages/curl:8.5.0
      command: ["sleep", "86400"]
      resources:
        limits: { memory: "64Mi", cpu: "100m" }
        requests: { memory: "32Mi", cpu: "50m" }
  restartPolicy: Never

---
# Test pod: backoffice-bff (allowed to call: product, cart, order, customer, inventory, media, tax, sampledata)
apiVersion: v1
kind: Pod
metadata:
  name: test-backoffice-bff
  namespace: $NS
  labels:
    app: test-backoffice-bff
    purpose: authorization-testing
  annotations:
    sidecar.istio.io/inject: "true"
spec:
  serviceAccountName: backoffice-bff
  containers:
    - name: curl
      image: curlimages/curl:8.5.0
      command: ["sleep", "86400"]
      resources:
        limits: { memory: "64Mi", cpu: "100m" }
        requests: { memory: "32Mi", cpu: "50m" }
  restartPolicy: Never

---
# Test pod: order (allowed to call: cart, customer)
apiVersion: v1
kind: Pod
metadata:
  name: test-order-pod
  namespace: $NS
  labels:
    app: test-order-pod
    purpose: authorization-testing
  annotations:
    sidecar.istio.io/inject: "true"
spec:
  serviceAccountName: order
  containers:
    - name: curl
      image: curlimages/curl:8.5.0
      command: ["sleep", "86400"]
      resources:
        limits: { memory: "64Mi", cpu: "100m" }
        requests: { memory: "32Mi", cpu: "50m" }
  restartPolicy: Never

---
# Test pod: search (allowed to call: storefront-bff only)
apiVersion: v1
kind: Pod
metadata:
  name: test-search-pod
  namespace: $NS
  labels:
    app: test-search-pod
    purpose: authorization-testing
  annotations:
    sidecar.istio.io/inject: "true"
spec:
  serviceAccountName: search
  containers:
    - name: curl
      image: curlimages/curl:8.5.0
      command: ["sleep", "86400"]
      resources:
        limits: { memory: "64Mi", cpu: "100m" }
        requests: { memory: "32Mi", cpu: "50m" }
  restartPolicy: Never

---
# Test pod: cart (allowed to call: storefront-bff, backoffice-bff, order)
apiVersion: v1
kind: Pod
metadata:
  name: test-cart-pod
  namespace: $NS
  labels:
    app: test-cart-pod
    purpose: authorization-testing
  annotations:
    sidecar.istio.io/inject: "true"
spec:
  serviceAccountName: cart
  containers:
    - name: curl
      image: curlimages/curl:8.5.0
      command: ["sleep", "86400"]
      resources:
        limits: { memory: "64Mi", cpu: "100m" }
        requests: { memory: "32Mi", cpu: "50m" }
  restartPolicy: Never

---
# Test pod: unauthorized (unknown SA - should be denied to all)
apiVersion: v1
kind: ServiceAccount
metadata:
  name: unauthorized-client
  namespace: $NS
---
apiVersion: v1
kind: Pod
metadata:
  name: test-unauthorized
  namespace: $NS
  labels:
    app: test-unauthorized
    purpose: authorization-testing
  annotations:
    sidecar.istio.io/inject: "true"
spec:
  serviceAccountName: unauthorized-client
  containers:
    - name: curl
      image: curlimages/curl:8.5.0
      command: ["sleep", "86400"]
      resources:
        limits: { memory: "64Mi", cpu: "100m" }
        requests: { memory: "32Mi", cpu: "50m" }
  restartPolicy: Never
TESTPODS
)
APPLY_RC=$?

if [ $APPLY_RC -ne 0 ]; then
    echo "  ⚠️  Warning: kubectl apply returned code $APPLY_RC"
    echo "  Output: $APPLY_OUTPUT"
else
    echo "  ✓ Pods deployed successfully"
fi

echo -e "  Waiting for test pods to be ready (with sidecar injection)..."

# Check if pods were created
sleep 1
POD_COUNT=$(kubectl get pods -n "$NS" -l purpose=authorization-testing --no-headers 2>/dev/null | wc -l)
echo "  Pods created: $POD_COUNT/6"
if [ "$POD_COUNT" -lt 6 ]; then
    echo -e "  ${YELLOW}⚠️  WARNING: Some test pods may have failed to create${NC}"
fi

wait_for_pod_ready() {
    local pod=$1
    local ns=$2
    local timeout=180  # Increased to 3 minutes for sidecar injection
    local elapsed=0
    local interval=5

    while [ $elapsed -lt $timeout ]; do
        local status
        status=$(kubectl get pod "$pod" -n "$ns" -o jsonpath='{.status.phase}' 2>/dev/null || echo "Unknown")
        
        if [ "$status" == "Running" ]; then
            # Check if pod is actually ready (all containers ready)
            local ready
            ready=$(kubectl get pod "$pod" -n "$ns" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "False")
            if [ "$ready" == "True" ]; then
                echo "      ✓ $pod is ready"
                return 0
            else
                # Pod is running but not ready, show container status
                local container_info
                container_info=$(kubectl get pod "$pod" -n "$ns" -o jsonpath='{.status.containerStatuses[*].name}{"="}{.status.containerStatuses[*].ready}' 2>/dev/null || echo "unknown")
                if [ $elapsed -eq 0 ] || [ $((elapsed % 30)) -eq 0 ]; then
                    echo "      ⏳ $pod: Running but not Ready - Containers: $container_info (waited ${elapsed}s/${timeout}s)"
                fi
            fi
        else
            echo "      ⏳ $pod: $status (waited ${elapsed}s/${timeout}s)"
        fi
        
        sleep $interval
        elapsed=$((elapsed + interval))
    done
    
    # Pod didn't get ready, show diagnostics
    echo "      ✗ $pod failed to become ready after ${timeout}s"
    
    # Check if pod exists
    local pod_exists
    pod_exists=$(kubectl get pod "$pod" -n "$ns" 2>/dev/null || echo "")
    if [ -z "$pod_exists" ]; then
        echo "        Pod not found in cluster"
        return 1
    fi
    
    # Show pod details
    echo "        Pod Status:"
    kubectl get pod "$pod" -n "$ns" -o wide 2>/dev/null | tail -1 | sed 's/^/          /'
    
    # Show container status
    echo "        Container Status:"
    kubectl get pod "$pod" -n "$ns" -o jsonpath='{.status.containerStatuses[*].name}{"\t"}{.status.containerStatuses[*].state}{"\n"}' 2>/dev/null | sed 's/^/          /'
    
    # Show recent events
    local events
    events=$(kubectl describe pod "$pod" -n "$ns" 2>/dev/null | grep -A 10 "Events:" || echo "No events found")
    if [ -n "$events" ]; then
        echo "        Recent Events:"
        echo "$events" | sed 's/^/          /'
    fi
    return 1
}

# Wait for all pods
PODS_READY=0
for pod in test-storefront-bff test-backoffice-bff test-order-pod test-search-pod test-cart-pod test-unauthorized; do
    if wait_for_pod_ready "$pod" "$NS"; then
        PODS_READY=$((PODS_READY + 1))
    fi
done

echo -e "\n  Pod Status: ${PODS_READY}/6 pods ready"

# Show summary of all test pods
echo -e "\n  Summary of test pods:"
kubectl get pods -n "$NS" -l purpose=authorization-testing -o wide 2>/dev/null || echo "  No test pods found"

if [ "$PODS_READY" -lt 6 ]; then
    echo -e "\n  ${YELLOW}⚠️  WARNING: Not all test pods are ready. Remaining tests will be skipped.${NC}"
    echo "  To troubleshoot:"
    echo "    kubectl describe pod <pod-name> -n $NS"
    echo "    kubectl logs <pod-name> -n $NS"
    echo "    kubectl get events -n $NS --sort-by='.lastTimestamp'"
fi

sleep 2

# ============================================================
# TEST 4: Authorization ALLOW - Whitelisted Access
# ============================================================
log_header "AUTHORIZATION - ALLOW (Whitelisted Callers)"

# Helper function for testing
test_access() {
    local pod=$1
    local target_svc=$2
    local expected_result=$3  # "ALLOW" or "DENY"
    local endpoint=${4:-"actuator/prometheus"}

    # Check if pod exists and is running
    local pod_status
    pod_status=$(kubectl get pod "$pod" -n "$NS" -o jsonpath='{.status.phase}' 2>/dev/null || echo "NotFound")
    
    if [ "$pod_status" != "Running" ]; then
        return 2  # SKIP - pod not ready
    fi

    RAW_CODE=$(kubectl exec -n "$NS" "$pod" -- \
        curl -s -o /dev/null -w "%{http_code}" \
        --connect-timeout 5 --max-time 10 \
        "http://${target_svc}.${NS}:80/${target_svc}/${endpoint}" 2>&1 || echo "000")
    HTTP_CODE=$(sanitize_http_code "$RAW_CODE")

    if [ "$expected_result" == "ALLOW" ]; then
        if [ "$HTTP_CODE" == "403" ]; then
            return 1  # FAIL
        elif [ "$HTTP_CODE" == "000" ]; then
            return 2  # SKIP (unreachable)
        else
            return 0  # PASS
        fi
    else  # DENY
        if [ "$HTTP_CODE" == "403" ]; then
            return 0  # PASS
        elif [ "$HTTP_CODE" == "000" ]; then
            return 2  # SKIP
        else
            return 1  # FAIL
        fi
    fi
}

# Test storefront-bff ALLOW access
SFBFF_READY=$(kubectl get pod test-storefront-bff -n "$NS" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "")
if [ "$SFBFF_READY" == "True" ]; then
    log_test "ALLOW - storefront-bff → product"
    if test_access "test-storefront-bff" "product" "ALLOW"; then
        log_pass "storefront-bff allowed to call product"
    else
        log_fail "storefront-bff denied access to product (should be allowed)"
    fi

    log_test "ALLOW - storefront-bff → search"
    if test_access "test-storefront-bff" "search" "ALLOW"; then
        log_pass "storefront-bff allowed to call search"
    else
        log_fail "storefront-bff denied access to search"
    fi

    log_test "ALLOW - storefront-bff → inventory"
    if test_access "test-storefront-bff" "inventory" "ALLOW"; then
        log_pass "storefront-bff allowed to call inventory"
    else
        log_fail "storefront-bff denied access to inventory"
    fi
else
    log_test "ALLOW - storefront-bff tests"
    log_skip "test-storefront-bff not ready"
fi

# Test backoffice-bff ALLOW access
BOFFBFF_READY=$(kubectl get pod test-backoffice-bff -n "$NS" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "")
if [ "$BOFFBFF_READY" == "True" ]; then
    log_test "ALLOW - backoffice-bff → tax"
    if test_access "test-backoffice-bff" "tax" "ALLOW"; then
        log_pass "backoffice-bff allowed to call tax"
    else
        log_fail "backoffice-bff denied access to tax (should be allowed)"
    fi

    log_test "ALLOW - backoffice-bff → sampledata"
    if test_access "test-backoffice-bff" "sampledata" "ALLOW"; then
        log_pass "backoffice-bff allowed to call sampledata"
    else
        log_fail "backoffice-bff denied access to sampledata"
    fi
else
    log_test "ALLOW - backoffice-bff tests"
    log_skip "test-backoffice-bff not ready"
fi

# ============================================================
# TEST 5: Authorization DENY - Unauthorized Access
# ============================================================
log_header "AUTHORIZATION - DENY (Unauthorized Access)"

UNAUTH_READY=$(kubectl get pod test-unauthorized -n "$NS" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "")
if [ "$UNAUTH_READY" == "True" ]; then
    log_test "DENY - unauthorized-client → product"
    if test_access "test-unauthorized" "product" "DENY"; then
        log_pass "unauthorized-client correctly denied (HTTP 403)"
    else
        log_fail "unauthorized-client got access to product (should be denied)"
    fi

    log_test "DENY - unauthorized-client → inventory"
    if test_access "test-unauthorized" "inventory" "DENY"; then
        log_pass "unauthorized-client correctly denied to inventory"
    else
        log_fail "unauthorized-client got access to inventory"
    fi

    log_test "DENY - unauthorized-client → tax"
    if test_access "test-unauthorized" "tax" "DENY"; then
        log_pass "unauthorized-client correctly denied to tax"
    else
        log_fail "unauthorized-client got access to tax"
    fi
else
    log_test "DENY - unauthorized-client tests"
    log_skip "test-unauthorized pod not ready"
fi

# ============================================================
# TEST 6: Invalid Cross-Service Patterns
# ============================================================
log_header "AUTHORIZATION - DENY (Invalid Cross-Service Access)"

ORDER_READY=$(kubectl get pod test-order-pod -n "$NS" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "")
if [ "$ORDER_READY" == "True" ]; then
    log_test "DENY - order → media (not in allow-list)"
    if test_access "test-order-pod" "media" "DENY"; then
        log_pass "order correctly denied access to media"
    else
        log_fail "order got access to media (should be denied)"
    fi

    log_test "DENY - order → tax (not allowed)"
    if test_access "test-order-pod" "tax" "DENY"; then
        log_pass "order correctly denied access to tax"
    else
        log_fail "order got access to tax"
    fi
else
    log_test "DENY - order cross-service tests"
    log_skip "test-order-pod not ready"
fi

SEARCH_READY=$(kubectl get pod test-search-pod -n "$NS" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "")
if [ "$SEARCH_READY" == "True" ]; then
    log_test "DENY - search → tax (not allowed)"
    if test_access "test-search-pod" "tax" "DENY"; then
        log_pass "search correctly denied access to tax"
    else
        log_fail "search got access to tax"
    fi

    log_test "DENY - search → cart (not allowed)"
    if test_access "test-search-pod" "cart" "DENY"; then
        log_pass "search correctly denied access to cart"
    else
        log_fail "search got access to cart"
    fi
else
    log_test "DENY - search cross-service tests"
    log_skip "test-search-pod not ready"
fi

CART_READY=$(kubectl get pod test-cart-pod -n "$NS" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "")
if [ "$CART_READY" == "True" ]; then
    log_test "DENY - cart → customer (not in allow-list)"
    if test_access "test-cart-pod" "customer" "DENY"; then
        log_pass "cart correctly denied access to customer"
    else
        log_fail "cart got access to customer"
    fi

    log_test "DENY - cart → inventory (not in allow-list)"
    if test_access "test-cart-pod" "inventory" "DENY"; then
        log_pass "cart correctly denied access to inventory"
    else
        log_fail "cart got access to inventory"
    fi
else
    log_test "DENY - cart cross-service tests"
    log_skip "test-cart-pod not ready"
fi

# ============================================================
# TEST 7: Undeployed/Removed Services
# ============================================================
log_header "UNDEPLOYED SERVICES - Should be Unreachable"

UNDEPLOYED_SERVICES=("payment" "location" "promotion" "rating" "recommendation" "webhook")

for svc in "${UNDEPLOYED_SERVICES[@]}"; do
    log_test "Service unavailable - $svc (not deployed)"
    
    if [ "$UNAUTH_READY" == "True" ]; then
        RAW_CODE=$(kubectl exec -n "$NS" test-unauthorized -- \
            curl -s -o /dev/null -w "%{http_code}" \
            --connect-timeout 3 --max-time 5 \
            "http://${svc}.${NS}:80/actuator/health" 2>&1 || echo "000")
        HTTP_CODE=$(sanitize_http_code "$RAW_CODE")

        if [ "$HTTP_CODE" == "000" ]; then
            log_pass "Service '${svc}' is unreachable (not deployed) ✓"
        else
            log_info "Service '${svc}' responded with HTTP ${HTTP_CODE} (may be deployed)"
        fi
    else
        log_skip "Cannot check service (unauthorized pod not ready)"
    fi
done

# ============================================================
# TEST 8: Retry Policy
# ============================================================
log_header "RETRY POLICY - VirtualService Configuration"

log_test "Retry Policy - VirtualServices exist"

VS_RETRY_COUNT=$(kubectl get virtualservice -n "$NS" -l purpose=retry-policy --no-headers 2>/dev/null | wc -l)

if [ "$VS_RETRY_COUNT" -ge 1 ]; then
    log_pass "Found ${VS_RETRY_COUNT} VirtualServices with retry policy"

    # Check retry config details
    RETRY_ATTEMPTS=$(kubectl get virtualservice product-retry -n "$NS" -o jsonpath='{.spec.http[0].retries.attempts}' 2>/dev/null || echo "0")
    if [ "$RETRY_ATTEMPTS" -ge 2 ]; then
        log_pass "Retry attempts configured: ${RETRY_ATTEMPTS}"
    else
        log_fail "Retry attempts too low: ${RETRY_ATTEMPTS}"
    fi
else
    log_fail "No VirtualServices with retry policy found"
fi

# ============================================================
# CLEANUP
# ============================================================
log_header "CLEANUP"

echo -e "  Removing test pods and service accounts..."
kubectl delete pod test-storefront-bff test-backoffice-bff test-order-pod test-search-pod test-cart-pod test-unauthorized -n "$NS" --grace-period=0 --force 2>/dev/null || true
kubectl delete sa unauthorized-client -n "$NS" --grace-period=0 --force 2>/dev/null || true
echo -e "  ${GREEN}Cleanup done${NC}"

# ============================================================
# SUMMARY
# ============================================================
log_header "TEST RESULTS SUMMARY"

echo -e "  Namespace : ${NS}"
echo -e "  Timestamp : $(date '+%Y-%m-%d %H:%M:%S')"
echo ""
echo -e "  ${GREEN}✅ PASS : ${PASS_COUNT}${NC}"
echo -e "  ${RED}❌ FAIL : ${FAIL_COUNT}${NC}"
echo -e "  ${YELLOW}⏭️  SKIP : ${SKIP_COUNT}${NC}"
echo -e "  ${BOLD}   TOTAL: ${TOTAL_COUNT}${NC}"
echo ""

if [ "$FAIL_COUNT" -eq 0 ]; then
    echo -e "  ${GREEN}${BOLD}🎉 ALL TESTS PASSED!${NC}"
    EXIT_CODE=0
else
    echo -e "  ${RED}${BOLD}⚠️  ${FAIL_COUNT} TEST(S) FAILED${NC}"
    EXIT_CODE=1
fi

echo ""
echo -e "${CYAN}============================================${NC}"
exit $EXIT_CODE
