#!/usr/bin/env bash
# Register or remove OAuth redirect URIs for developer_build NodePort BFF access.
set -euo pipefail

KEYCLOAK_NS="${KEYCLOAK_NS:-keycloak}"
KEYCLOAK_SVC="${KEYCLOAK_SVC:-keycloak-service}"
KEYCLOAK_REALM="${KEYCLOAK_REALM:-Yas}"
# Set KEYCLOAK_URL explicitly to skip port-forward (e.g. when running inside the cluster).
KEYCLOAK_URL="${KEYCLOAK_URL:-}"
KEYCLOAK_PF_PORT="${KEYCLOAK_PF_PORT:-}"
KEYCLOAK_PF_PID=""
CONFIGMAP_NAME="${CONFIGMAP_NAME:-developer-keycloak-redirects}"

usage() {
  cat <<'EOF'
Usage:
  manage-dev-redirects.sh register --namespace NS --storefront-port PORT --backoffice-port PORT [--worker-ip IP]
  manage-dev-redirects.sh unregister --namespace NS

register: add redirect URIs to Keycloak clients and save them in a ConfigMap in NS.
unregister: read ConfigMap from NS, remove URIs from Keycloak, then caller may delete NS.
EOF
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "ERROR: '$1' is required"; exit 1; }
}

stop_keycloak_port_forward() {
  if [ -n "$KEYCLOAK_PF_PID" ]; then
    kill "$KEYCLOAK_PF_PID" 2>/dev/null || true
    wait "$KEYCLOAK_PF_PID" 2>/dev/null || true
    KEYCLOAK_PF_PID=""
  fi
}

# Self-hosted runners often cannot resolve *.svc.cluster.local or reach ClusterIP directly.
ensure_keycloak_url() {
  if [ -n "$KEYCLOAK_URL" ]; then
    return 0
  fi

  if ! kubectl get svc "$KEYCLOAK_SVC" -n "$KEYCLOAK_NS" &>/dev/null; then
    echo "ERROR: Keycloak service $KEYCLOAK_SVC not found in $KEYCLOAK_NS"
    exit 1
  fi

  KEYCLOAK_PF_PORT=$((18080 + RANDOM % 1000))
  echo "Starting kubectl port-forward to Keycloak on 127.0.0.1:${KEYCLOAK_PF_PORT}..."
  kubectl port-forward -n "$KEYCLOAK_NS" "svc/${KEYCLOAK_SVC}" "${KEYCLOAK_PF_PORT}:80" >/dev/null 2>&1 &
  KEYCLOAK_PF_PID=$!
  trap stop_keycloak_port_forward EXIT

  local i
  for i in $(seq 1 25); do
    if curl -sf -m 2 "http://127.0.0.1:${KEYCLOAK_PF_PORT}/realms/master" >/dev/null 2>&1; then
      KEYCLOAK_URL="http://127.0.0.1:${KEYCLOAK_PF_PORT}"
      echo "Using Keycloak Admin API at $KEYCLOAK_URL"
      return 0
    fi
    sleep 1
  done

  echo "ERROR: Keycloak port-forward did not become ready (see kubectl port-forward)"
  exit 1
}

keycloak_token() {
  ensure_keycloak_url

  local user pass response http_code
  user=$(kubectl get secret keycloak-credentials -n "$KEYCLOAK_NS" -o jsonpath='{.data.username}' 2>/dev/null | base64 -d)
  pass=$(kubectl get secret keycloak-credentials -n "$KEYCLOAK_NS" -o jsonpath='{.data.password}' 2>/dev/null | base64 -d)
  if [ -z "$user" ] || [ -z "$pass" ]; then
    echo "ERROR: cannot read keycloak-credentials secret in namespace $KEYCLOAK_NS"
    exit 1
  fi

  response=$(curl -sS -m 30 -w "\n%{http_code}" -X POST "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=${user}" \
    -d "password=${pass}" \
    -d "grant_type=password" \
    -d "client_id=admin-cli")
  http_code=$(echo "$response" | tail -n1)
  response=$(echo "$response" | sed '$d')

  if [ "$http_code" != "200" ]; then
    echo "ERROR: Keycloak token request failed (HTTP $http_code): $response"
    exit 1
  fi

  local token
  token=$(echo "$response" | jq -r '.access_token // empty')
  if [ -z "$token" ] || [ "$token" = "null" ]; then
    echo "ERROR: Keycloak token response missing access_token"
    exit 1
  fi
  echo "$token"
}

curl_keycloak() {
  if [ -z "${KEYCLOAK_URL:-}" ]; then
    echo "ERROR: KEYCLOAK_URL is not set (call ensure_keycloak_url first)"
    exit 1
  fi
  curl "$@"
}

client_uuid() {
  local token=$1 client_id=$2
  curl_keycloak -sf "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/clients?clientId=${client_id}" \
    -H "Authorization: Bearer ${token}" \
    | jq -r '.[0].id // empty'
}

update_client_redirects() {
  local token=$1 client_id=$2 mode=$3
  shift 3
  local uris=("$@")

  local uuid
  uuid=$(client_uuid "$token" "$client_id")
  if [ -z "$uuid" ]; then
    echo "ERROR: Keycloak client '$client_id' not found"
    exit 1
  fi

  local client_json new_redirects
  client_json=$(curl_keycloak -sf "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/clients/${uuid}" \
    -H "Authorization: Bearer ${token}")

  if [ "$mode" = "add" ]; then
    new_redirects=$(echo "$client_json" | jq --argjson add "$(printf '%s\n' "${uris[@]}" | jq -R . | jq -s .)" \
      '.redirectUris // [] | . + $add | unique')
  else
    new_redirects=$(echo "$client_json" | jq --argjson rm "$(printf '%s\n' "${uris[@]}" | jq -R . | jq -s .)" \
      '.redirectUris // [] | map(select(. as $u | ($rm | index($u)) | not))')
  fi

  echo "$client_json" | jq --argjson redirects "$new_redirects" '.redirectUris = $redirects' \
    | curl_keycloak -sf -X PUT "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/clients/${uuid}" \
      -H "Authorization: Bearer ${token}" \
      -H "Content-Type: application/json" \
      -d @- >/dev/null

  echo "  $client_id: ${mode} ${uris[*]}"
}

build_redirect_uris() {
  local storefront_port=$1 backoffice_port=$2 worker_ip=${3:-}

  STOREFRONT_URIS=("http://localhost:${storefront_port}/*")
  BACKOFFICE_URIS=("http://localhost:${backoffice_port}/*")

  if [ -n "$worker_ip" ] && [ "$worker_ip" != "<WORKER_NODE_IP>" ]; then
    STOREFRONT_URIS+=("http://${worker_ip}:${storefront_port}/*")
    BACKOFFICE_URIS+=("http://${worker_ip}:${backoffice_port}/*")
  fi
}

cmd_register() {
  local ns=$1 storefront_port=$2 backoffice_port=$3 worker_ip=${4:-}

  if [ "$storefront_port" = "N/A" ] || [ "$backoffice_port" = "N/A" ]; then
    echo "ERROR: invalid NodePort (storefront=$storefront_port backoffice=$backoffice_port)"
    exit 1
  fi

  if ! kubectl get svc "$KEYCLOAK_SVC" -n "$KEYCLOAK_NS" &>/dev/null; then
    echo "WARN: Keycloak service not found, skipping redirect registration"
    exit 0
  fi

  build_redirect_uris "$storefront_port" "$backoffice_port" "$worker_ip"

  echo "Registering Keycloak redirect URIs for namespace $ns..."
  ensure_keycloak_url
  local token
  token=$(keycloak_token)

  update_client_redirects "$token" "storefront-bff" add "${STOREFRONT_URIS[@]}"
  update_client_redirects "$token" "backoffice-bff" add "${BACKOFFICE_URIS[@]}"

  local payload
  payload=$(jq -n \
    --arg sf "$(printf '%s\n' "${STOREFRONT_URIS[@]}")" \
    --arg bo "$(printf '%s\n' "${BACKOFFICE_URIS[@]}")" \
    '{
      "storefront-bff": ($sf | split("\n") | map(select(length > 0))),
      "backoffice-bff": ($bo | split("\n") | map(select(length > 0)))
    }')

  kubectl create configmap "$CONFIGMAP_NAME" -n "$ns" \
    --from-literal=redirects.json="$payload" \
    --dry-run=client -o yaml | kubectl apply -f -

  echo "Saved redirect URIs to ConfigMap $CONFIGMAP_NAME in $ns"
}

cmd_unregister() {
  local ns=$1

  if ! kubectl get configmap "$CONFIGMAP_NAME" -n "$ns" &>/dev/null; then
    echo "No $CONFIGMAP_NAME in $ns, skipping Keycloak redirect cleanup"
    return 0
  fi

  if ! kubectl get svc "$KEYCLOAK_SVC" -n "$KEYCLOAK_NS" &>/dev/null; then
    echo "WARN: Keycloak service not found, skipping redirect removal"
    return 0
  fi

  local payload sf_uris bo_uris token
  payload=$(kubectl get configmap "$CONFIGMAP_NAME" -n "$ns" -o jsonpath='{.data.redirects\.json}')
  mapfile -t sf_uris < <(echo "$payload" | jq -r '.["storefront-bff"][]?')
  mapfile -t bo_uris < <(echo "$payload" | jq -r '.["backoffice-bff"][]?')

  if [ "${#sf_uris[@]}" -eq 0 ] && [ "${#bo_uris[@]}" -eq 0 ]; then
    echo "ConfigMap $CONFIGMAP_NAME in $ns is empty, nothing to remove"
    return 0
  fi

  echo "Removing Keycloak redirect URIs for namespace $ns..."
  ensure_keycloak_url
  token=$(keycloak_token)

  if [ "${#sf_uris[@]}" -gt 0 ]; then
    update_client_redirects "$token" "storefront-bff" remove "${sf_uris[@]}"
  fi
  if [ "${#bo_uris[@]}" -gt 0 ]; then
    update_client_redirects "$token" "backoffice-bff" remove "${bo_uris[@]}"
  fi

  kubectl delete configmap "$CONFIGMAP_NAME" -n "$ns" --ignore-not-found
  echo "Removed redirect URIs and deleted ConfigMap $CONFIGMAP_NAME from $ns"
}

main() {
  require_cmd kubectl
  require_cmd curl
  require_cmd jq

  local cmd=${1:-}
  shift || true

  case "$cmd" in
    register)
      local ns="" sf="" bo="" worker_ip=""
      while [ $# -gt 0 ]; do
        case "$1" in
          --namespace) ns=$2; shift 2 ;;
          --storefront-port) sf=$2; shift 2 ;;
          --backoffice-port) bo=$2; shift 2 ;;
          --worker-ip) worker_ip=$2; shift 2 ;;
          *) echo "Unknown arg: $1"; usage; exit 1 ;;
        esac
      done
      [ -n "$ns" ] && [ -n "$sf" ] && [ -n "$bo" ] || { usage; exit 1; }
      cmd_register "$ns" "$sf" "$bo" "$worker_ip"
      ;;
    unregister)
      local ns=""
      while [ $# -gt 0 ]; do
        case "$1" in
          --namespace) ns=$2; shift 2 ;;
          *) echo "Unknown arg: $1"; usage; exit 1 ;;
        esac
      done
      [ -n "$ns" ] || { usage; exit 1; }
      cmd_unregister "$ns"
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"
