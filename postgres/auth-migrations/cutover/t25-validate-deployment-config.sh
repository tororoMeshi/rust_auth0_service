#!/usr/bin/env bash
set -euo pipefail

# T25 validates only the committed deployment/configuration contract.
repo_root="$(cd "$(dirname "$BASH_SOURCE")/../../.." && pwd -P)"
kubectl_command="${KUBECTL:-kubectl}"
backend_deployment="$repo_root/portal_backend/k8s/deploy.yaml"
backend_service="$repo_root/portal_backend/k8s/service.yaml"
backend_configmap="$repo_root/portal_backend/k8s/backend-configmap.yaml"
frontend_deployment="$repo_root/portal/k8s/frontend-deployment.yaml"
frontend_service="$repo_root/portal/k8s/frontend-service.yaml"
frontend_configmap="$repo_root/portal/k8s/frontend-configmap.yaml"

validate_structure() {
    python3 - "$@" <<'PY'
import re
import sys
import yaml

backend_deploy_path, backend_service_path, backend_config_path, frontend_deploy_path, frontend_service_path, frontend_config_path = sys.argv[1:]

def fail(message):
    raise SystemExit(f"T25 deployment/configuration preflight failed: {message}")

def require(condition, message):
    if not condition:
        fail(message)

def load(path):
    with open(path, encoding="utf-8") as source:
        document = yaml.safe_load(source)
    require(isinstance(document, dict), f"{path}: expected a YAML mapping")
    return document

def named(items, name):
    return next((item for item in items if item.get("name") == name), None)

def name(document):
    return document.get("metadata", {}).get("name")

def locations(nginx_config):
    # Structured nginx location extraction; this is not substring matching.
    config = re.sub(r"(?m)#.*$", "", nginx_config)
    require(config.count("{") == config.count("}"), "nginx.conf has unbalanced braces")
    blocks = {}
    pattern = re.compile(
        r"(?ms)^[ \t]*location[ \t]+(?:(?P<modifier>=|\^~|~\*|~)[ \t]+)?"
        r"(?P<path>[^ \t{]+)[ \t]*\{(?P<body>.*?)^[ \t]*\}"
    )
    for match in pattern.finditer(config):
        key = (match.group("modifier") or "", match.group("path"))
        require(key not in blocks, f"nginx.conf has duplicate location {key}")
        blocks[key] = match.group("body")
    require(blocks, "nginx.conf has no parsed location blocks")
    return blocks

def proxy_passes(body):
    return re.findall(r"(?m)^[ \t]*proxy_pass[ \t]+([^;]+);", body)

backend_deploy = load(backend_deploy_path)
backend_service = load(backend_service_path)
backend_config = load(backend_config_path)
frontend_deploy = load(frontend_deploy_path)
frontend_service = load(frontend_service_path)
frontend_config = load(frontend_config_path)

require(
    backend_deploy.get("apiVersion") == "apps/v1"
    and backend_deploy.get("kind") == "Deployment"
    and name(backend_deploy) == "portal-backend-deployment",
    "portal backend Deployment identity is wrong",
)
backend_pod = backend_deploy.get("spec", {}).get("template", {}).get("spec", {})
backend = named(backend_pod.get("containers", []), "portal-backend")
require(backend is not None, "portal-backend container is missing")
secret_env = named(backend.get("env", []), "PORTAL_SERVICE_SECRET")
require(secret_env is not None, "PORTAL_SERVICE_SECRET is missing")
require(
    secret_env.get("valueFrom", {}).get("secretKeyRef", {}) == {
        "name": "portal-prod-service-secret", "key": "service_secret"
    },
    "PORTAL_SERVICE_SECRET must reference portal-prod-service-secret key service_secret",
)
for env_name in ("PORTAL_SERVICE_ID", "PORTAL_AUTH_FOUNDATION_BASE_URL"):
    env = named(backend.get("env", []), env_name)
    require(
        env is not None
        and env.get("valueFrom", {}).get("configMapKeyRef", {}) == {
            "name": "backend-config", "key": env_name
        },
        f"{env_name} must reference backend-config",
    )
require(
    backend_config.get("kind") == "ConfigMap"
    and name(backend_config) == "backend-config"
    and backend_config.get("data", {}).get("PORTAL_SERVICE_ID") == "portal-prod"
    and backend_config.get("data", {}).get("PORTAL_AUTH_FOUNDATION_BASE_URL") == "https://auth.tororomeshi.net",
    "backend-config does not provide the runtime identity/base URL contract",
)
backend_labels = backend_deploy.get("spec", {}).get("template", {}).get("metadata", {}).get("labels", {})
require(
    backend_deploy.get("spec", {}).get("selector", {}).get("matchLabels", {}) == backend_labels == {"app": "portal-backend"}
    and backend_service.get("kind") == "Service"
    and name(backend_service) == "portal-backend-service"
    and backend_service.get("spec", {}).get("selector") == backend_labels
    and backend_service.get("spec", {}).get("ports") == [{"name": "http", "port": 3000, "targetPort": 3000, "protocol": "TCP"}]
    and backend.get("ports") == [{"containerPort": 3000, "name": "http"}],
    "portal backend Service/Deployment relationship is inconsistent",
)

require(
    frontend_deploy.get("kind") == "Deployment" and name(frontend_deploy) == "frontend-deployment",
    "frontend Deployment identity is wrong",
)
frontend_pod = frontend_deploy.get("spec", {}).get("template", {}).get("spec", {})
frontend = named(frontend_pod.get("containers", []), "frontend")
frontend_labels = frontend_deploy.get("spec", {}).get("template", {}).get("metadata", {}).get("labels", {})
require(
    frontend is not None
    and frontend_deploy.get("spec", {}).get("selector", {}).get("matchLabels", {}) == frontend_labels == {"app": "frontend"}
    and frontend_service.get("kind") == "Service"
    and name(frontend_service) == "frontend-service"
    and frontend_service.get("spec", {}).get("selector") == frontend_labels
    and frontend.get("ports") == [{"containerPort": 8080}]
    and frontend_service.get("spec", {}).get("ports") == [{"name": "http", "port": 80, "targetPort": 8080, "protocol": "TCP"}],
    "frontend Service/Deployment relationship is inconsistent",
)
volume = named(frontend_pod.get("volumes", []), "nginx-config")
require(
    volume is not None and volume.get("configMap", {}).get("name") == "frontend-config",
    "frontend does not mount frontend-config",
)
frontend_volume_mount = named(frontend.get("volumeMounts", []), "nginx-config")
require(
    frontend_volume_mount is not None
    and frontend_volume_mount.get("name") == volume.get("name")
    and frontend_volume_mount.get("mountPath") == "/etc/nginx/nginx.conf"
    and frontend_volume_mount.get("subPath") == "nginx.conf",
    "frontend container does not mount frontend-config as /etc/nginx/nginx.conf via subPath nginx.conf",
)
require(frontend_config.get("kind") == "ConfigMap" and name(frontend_config) == "frontend-config", "frontend ConfigMap identity is wrong")
nginx_config = frontend_config.get("data", {}).get("nginx.conf")
require(isinstance(nginx_config, str), "frontend-config lacks nginx.conf")
route_blocks = locations(nginx_config)
for route in {("=", "/login"), ("=", "/auth/callback"), ("=", "/logout"), ("=", "/api"), ("^~", "/api/")}:
    require(route in route_blocks, f"nginx.conf lacks required location {route}")
    require(proxy_passes(route_blocks[route]) == ["http://portal-backend-service:3000"], f"{route} does not proxy only to portal-backend-service:3000")
for legacy in ("/auth/google", "/upsert_and_token", "/sessions/verify"):
    require(not any(path == legacy or path.startswith(legacy + "/") for _, path in route_blocks), f"nginx.conf reintroduces {legacy}")

print("T25 structural deployment/configuration validation passed")
PY
}

extract_nginx_config() {
    python3 - "$frontend_configmap" <<'PY'
import sys
import yaml
with open(sys.argv[1], encoding="utf-8") as source:
    print(yaml.safe_load(source)["data"]["nginx.conf"], end="")
PY
}

validate_nginx_syntax_if_available() {
    local config_path="$1"
    if command -v nginx >/dev/null 2>&1; then
        nginx -t -c "$config_path"
    elif command -v docker >/dev/null 2>&1 && docker image inspect nginx:1.29-alpine >/dev/null 2>&1; then
        docker run --pull=never --rm -v "$config_path:/etc/nginx/nginx.conf:ro" nginx:1.29-alpine nginx -t
    else
        printf 'T25 nginx syntax tool unavailable locally; nginx route blocks were parsed structurally\n'
    fi
}

negative_secret() {
    local temp_dir
    temp_dir="$(mktemp -d)"
    python3 - "$backend_deployment" "$temp_dir/deploy.yaml" <<'PY'
import sys
import yaml
with open(sys.argv[1], encoding="utf-8") as source:
    document = yaml.safe_load(source)
container = next(c for c in document["spec"]["template"]["spec"]["containers"] if c["name"] == "portal-backend")
next(e for e in container["env"] if e["name"] == "PORTAL_SERVICE_SECRET")["valueFrom"]["secretKeyRef"].pop("key")
with open(sys.argv[2], "w", encoding="utf-8") as target:
    yaml.safe_dump(document, target, sort_keys=False)
PY
    if validate_structure "$temp_dir/deploy.yaml" "$backend_service" "$backend_configmap" "$frontend_deployment" "$frontend_service" "$frontend_configmap"; then
        rm -rf "$temp_dir"; printf 'T25 negative Secret-reference test unexpectedly passed\n' >&2; return 1
    fi
    rm -rf "$temp_dir"; printf 'T25 negative Secret-reference test passed\n'
}

negative_routing() {
    local temp_dir
    temp_dir="$(mktemp -d)"
    python3 - "$frontend_configmap" "$temp_dir/frontend-configmap.yaml" <<'PY'
import re
import sys
import yaml
with open(sys.argv[1], encoding="utf-8") as source:
    document = yaml.safe_load(source)
document["data"]["nginx.conf"] = re.sub(r"(?ms)^\s*location\s+=\s+/api\s*\{.*?^\s*\}\n?", "", document["data"]["nginx.conf"], count=1)
with open(sys.argv[2], "w", encoding="utf-8") as target:
    yaml.safe_dump(document, target, sort_keys=False)
PY
    if validate_structure "$backend_deployment" "$backend_service" "$backend_configmap" "$frontend_deployment" "$frontend_service" "$temp_dir/frontend-configmap.yaml"; then
        rm -rf "$temp_dir"; printf 'T25 negative routing test unexpectedly passed\n' >&2; return 1
    fi
    rm -rf "$temp_dir"; printf 'T25 negative routing test passed\n'
}

negative_frontend_mount() {
    local temp_dir
    temp_dir="$(mktemp -d)"
    python3 - "$frontend_deployment" "$temp_dir/frontend-deployment.yaml" <<'PY'
import sys
import yaml
with open(sys.argv[1], encoding="utf-8") as source:
    document = yaml.safe_load(source)
container = next(c for c in document["spec"]["template"]["spec"]["containers"] if c["name"] == "frontend")
container["volumeMounts"] = [mount for mount in container.get("volumeMounts", []) if mount.get("name") != "nginx-config"]
with open(sys.argv[2], "w", encoding="utf-8") as target:
    yaml.safe_dump(document, target, sort_keys=False)
PY
    if validate_structure "$backend_deployment" "$backend_service" "$backend_configmap" "$temp_dir/frontend-deployment.yaml" "$frontend_service" "$frontend_configmap"; then
        rm -rf "$temp_dir"; printf 'T25 negative frontend volumeMount test unexpectedly passed\n' >&2; return 1
    fi
    rm -rf "$temp_dir"; printf 'T25 negative frontend volumeMount test passed\n'
}

mode="${1:-}"
case "$mode" in
    "")
        "$kubectl_command" kustomize "$repo_root/portal/k8s" | "$kubectl_command" apply --dry-run=client --validate=false -f - >/dev/null
        "$kubectl_command" apply --dry-run=client --validate=false -f "$repo_root/rust-auth0-service/yaml/deploy.yaml" -f "$repo_root/rust-auth0-service/yaml/service.yaml" -f "$backend_configmap" -f "$backend_deployment" -f "$backend_service" -f "$repo_root/portal_backend/k8s/backend-networkpolicy.yaml" >/dev/null
        validate_structure "$backend_deployment" "$backend_service" "$backend_configmap" "$frontend_deployment" "$frontend_service" "$frontend_configmap"
        nginx_config_temp="$(mktemp)"
        trap 'rm -f "$nginx_config_temp"' EXIT
        extract_nginx_config >"$nginx_config_temp"
        validate_nginx_syntax_if_available "$nginx_config_temp"
        ;;
    --negative-secret) negative_secret ;;
    --negative-routing) negative_routing ;;
    --negative-frontend-mount) negative_frontend_mount ;;
    *) printf 'usage: %s [--negative-secret|--negative-routing|--negative-frontend-mount]\n' "$0" >&2; exit 64 ;;
esac
