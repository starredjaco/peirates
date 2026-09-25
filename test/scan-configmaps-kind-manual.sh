#!/usr/bin/env bash
# This manual Kind test creates a disposable ConfigMap credential fixture and
# attaches the full Peirates menu to the operator's terminal.
#
# The script tests:
# - A real kubelet client certificate, an allowed stored service-account token,
#   and a denied stored token against independently checked ConfigMap RBAC.
# - JWTs in data and binaryData, an SSH private key, and AWS, Google, and Azure
#   credential-shaped fixtures, with a clean ConfigMap as a negative control.
# - Operator-entered numeric or named dispatch and credential redaction.
# - API fixture and RBAC state before and after the interactive session.
# - Claim-aware cleanup of only the cluster created by this invocation.

set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${root_dir}/test/kind-build-helpers.sh"
# Keep the worker in the foreground so Docker can attach Peirates to the
# controlling terminal. EXIT and signal traps clean up the proven-owned cluster.
cluster_name="${PEIRATES_SCAN_CONFIGMAPS_MANUAL_CLUSTER:-peirates-scan-configmaps-manual}"
context="kind-${cluster_name}"
node_name="${cluster_name}-control-plane"
namespace="default"
allowed_account="peirates-scan-allowed"
denied_account="peirates-scan-denied"
allowed_secret="peirates-scan-allowed-token-live"
denied_secret="peirates-scan-denied-token-live"
runner_pod="peirates-scan-token-mounts"
fixture_map="peirates-scan-credentials"
clean_map="peirates-scan-clean"
role_name="peirates-scan-reader"
kubeconfig_file=""
config_file=""
pod_file=""
peirates_binary=""
ssh_key_file=""
node_cert_file=""
cluster_claim=""
cluster_ownership=none

cleanup() {
    finish_kind_script_cleanup "$?" "${cluster_name}" "${kubeconfig_file}" \
        "${cluster_ownership}" "${cluster_claim}" \
        "${config_file}" "${pod_file}" "${peirates_binary}" \
        "${ssh_key_file}" "${ssh_key_file}.pub" "${node_cert_file}" \
        "${kubeconfig_file}"
}
install_kind_script_traps cleanup

if [[ ! -t 0 || ! -t 1 ]]; then
    echo "scan-configmaps manual test requires an interactive terminal" >&2
    exit 1
fi

kubeconfig_file="$(mktemp /tmp/peirates-kind-kubeconfig.XXXXXX)"
chmod 600 "${kubeconfig_file}"
export KUBECONFIG="${kubeconfig_file}"
config_file="$(mktemp /tmp/peirates-scan-configmaps-kind.XXXXXX.yaml)"
pod_file="$(mktemp /tmp/peirates-scan-configmaps-pod.XXXXXX.yaml)"
peirates_binary="$(mktemp /tmp/peirates-scan-configmaps-binary.XXXXXX)"
ssh_key_file="$(mktemp /tmp/peirates-scan-configmaps-ssh.XXXXXX)"
node_cert_file="$(mktemp /tmp/peirates-scan-configmaps-node-cert.XXXXXX)"

for required in kind kubectl docker go base64 openssl ssh-keygen grep find; do
    command -v "${required}" >/dev/null || { echo "missing required command: ${required}" >&2; exit 1; }
done
acquire_kind_cluster_claim "${cluster_name}" cluster_claim
require_absent_kind_cluster "${cluster_name}"

cat >"${config_file}" <<'CONFIG'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
CONFIG
create_kind_cluster_with_provenance "${cluster_name}" "${kubeconfig_file}" \
    cluster_ownership --config "${config_file}" --wait 120s

# Verify the node certificate subject before relying on Peirates discovery.
docker exec "${node_name}" cat /var/lib/kubelet/pki/kubelet-client-current.pem \
    >"${node_cert_file}"
if ! openssl x509 -in "${node_cert_file}" -noout -subject -nameopt RFC2253 |
    grep -Fq "CN=system:node:${node_name}"; then
    echo "Kind kubelet certificate has an unexpected subject" >&2
    exit 1
fi

kubectl --context "${context}" -n "${namespace}" create serviceaccount "${allowed_account}"
kubectl --context "${context}" -n "${namespace}" create serviceaccount "${denied_account}"
kubectl --context "${context}" -n "${namespace}" create role "${role_name}" \
    --verb=list --resource=configmaps
kubectl --context "${context}" -n "${namespace}" create rolebinding "${role_name}" \
    --role="${role_name}" --serviceaccount="${namespace}:${allowed_account}"

# A cluster-scoped grant lets the certificate cover every namespace, while the
# allowed token must use the scanner's current-namespace fallback.
kubectl --context "${context}" create clusterrole "${role_name}" \
    --verb=list --resource=configmaps
kubectl --context "${context}" create clusterrolebinding "${role_name}" \
    --clusterrole="${role_name}" --user="system:node:${node_name}"

node_identity="system:node:${node_name}"
allowed_identity="system:serviceaccount:${namespace}:${allowed_account}"
denied_identity="system:serviceaccount:${namespace}:${denied_account}"
if [[ "$(kubectl --context "${context}" auth can-i list configmaps --all-namespaces \
    --as="${node_identity}")" != yes ]]; then
    echo "node certificate identity cannot list cluster ConfigMaps" >&2
    exit 1
fi
if [[ "$(kubectl --context "${context}" auth can-i list configmaps -n "${namespace}" \
    --as="${allowed_identity}")" != yes ||
    "$(kubectl --context "${context}" auth can-i list configmaps --all-namespaces \
    --as="${allowed_identity}")" != no ]]; then
    echo "allowed token RBAC does not match namespace-only fixture" >&2
    exit 1
fi
for denied_scope in "-n ${namespace}" "--all-namespaces"; do
    # Word splitting is intentional for the two constant kubectl scope forms.
    if [[ "$(kubectl --context "${context}" auth can-i list configmaps \
        ${denied_scope} --as="${denied_identity}")" != no ]]; then
        echo "denied token unexpectedly can list ConfigMaps" >&2
        exit 1
    fi
done

# Generate a valid JWT-shaped marker and a real OpenSSH private key. All cloud
# values are disposable format examples with no usable account behind them.
jwt_header="$(printf '{"alg":"HS256","typ":"JWT"}' | base64 | tr -d '\n=' | tr '+/' '-_')"
jwt_payload="$(printf '{"sub":"peirates-kind-fixture"}' | base64 | tr -d '\n=' | tr '+/' '-_')"
jwt_value="${jwt_header}.${jwt_payload}.c2lnbmF0dXJl"
aws_key_id="ASIAPEIRATESDEMO1234"
gcp_token="ya29.a0AfH6SMBPeiratesDisposableAccessToken123456"
azure_sas="sv=2023-11-03&se=2030-01-01T00%3A00%3A00Z&sp=r&sig=PeiratesDisposableSignature%3D"
rm -f -- "${ssh_key_file}"
ssh-keygen -q -t ed25519 -N '' -f "${ssh_key_file}"

kubectl --context "${context}" -n "${namespace}" create configmap "${fixture_map}" \
    --from-literal="jwt-text=prefix ${jwt_value} suffix" \
    --from-file="ssh-private-key=${ssh_key_file}" \
    --from-literal="aws-session=AWS_ACCESS_KEY_ID=${aws_key_id}" \
    --from-literal="gcp-access=${gcp_token}" \
    --from-literal="azure-sas=${azure_sas}"
binary_jwt="$(printf 'prefix:%s\000suffix' "${jwt_value}" | base64 | tr -d '\n')"
kubectl --context "${context}" -n "${namespace}" patch configmap "${fixture_map}" \
    --type=merge -p "{\"binaryData\":{\"binary-jwt\":\"${binary_jwt}\"}}"
kubectl --context "${context}" -n "${namespace}" create configmap "${clean_map}" \
    --from-literal='plain=ordinary configuration without credential markers'

# Check the persisted fields through the API, independent of Peirates output.
if [[ "$(kubectl --context "${context}" -n "${namespace}" get configmap "${fixture_map}" \
    -o jsonpath='{.data.jwt-text}')" != "prefix ${jwt_value} suffix" ||
    "$(kubectl --context "${context}" -n "${namespace}" get configmap "${fixture_map}" \
    -o jsonpath='{.binaryData.binary-jwt}')" != "${binary_jwt}" ]]; then
    echo "ConfigMap JWT fixtures differ from the values submitted" >&2
    exit 1
fi
if [[ "$(kubectl --context "${context}" -n "${namespace}" get configmap "${fixture_map}" \
    -o jsonpath='{.data.aws-session}')" != "AWS_ACCESS_KEY_ID=${aws_key_id}" ||
    "$(kubectl --context "${context}" -n "${namespace}" get configmap "${fixture_map}" \
    -o jsonpath='{.data.gcp-access}')" != "${gcp_token}" ||
    "$(kubectl --context "${context}" -n "${namespace}" get configmap "${fixture_map}" \
    -o jsonpath='{.data.azure-sas}')" != "${azure_sas}" ]]; then
    echo "ConfigMap cloud fixtures differ from the values submitted" >&2
    exit 1
fi
if [[ "$(kubectl --context "${context}" -n "${namespace}" get configmap "${fixture_map}" \
    -o jsonpath='{.data.ssh-private-key}')" != "$(cat "${ssh_key_file}")" ||
    "$(kubectl --context "${context}" -n "${namespace}" get configmap "${clean_map}" \
    -o jsonpath='{.data.plain}')" != 'ordinary configuration without credential markers' ]]; then
    echo "ConfigMap SSH or clean fixture differs from the value submitted" >&2
    exit 1
fi

# Controller-populated token Secrets become node-visible pod volumes. Their
# names include -token- so Peirates' existing node discovery imports them.
for token_fixture in \
    "${allowed_secret}:${allowed_account}" \
    "${denied_secret}:${denied_account}"; do
    secret_name="${token_fixture%%:*}"
    service_account="${token_fixture#*:}"
    kubectl --context "${context}" -n "${namespace}" apply -f - <<TOKEN_SECRET
apiVersion: v1
kind: Secret
metadata:
  name: ${secret_name}
  annotations:
    kubernetes.io/service-account.name: ${service_account}
type: kubernetes.io/service-account-token
TOKEN_SECRET
    kubectl --context "${context}" -n "${namespace}" wait \
        --for=jsonpath='{.data.token}' "secret/${secret_name}" --timeout=60s
done

cat >"${pod_file}" <<RUNNER_POD
apiVersion: v1
kind: Pod
metadata:
  name: ${runner_pod}
  namespace: ${namespace}
spec:
  serviceAccountName: ${denied_account}
  containers:
  - name: mounts
    image: busybox:1.36.1
    command: ["sh", "-c", "sleep 3600"]
    volumeMounts:
    - name: ${allowed_secret}
      mountPath: /var/run/peirates-allowed-token
      readOnly: true
    - name: ${denied_secret}
      mountPath: /var/run/peirates-denied-token
      readOnly: true
  volumes:
  - name: ${allowed_secret}
    secret:
      secretName: ${allowed_secret}
  - name: ${denied_secret}
    secret:
      secretName: ${denied_secret}
RUNNER_POD
kubectl --context "${context}" apply -f "${pod_file}"
kubectl --context "${context}" -n "${namespace}" wait \
    --for=condition=Ready "pod/${runner_pod}" --timeout=120s

for token_secret in "${allowed_secret}" "${denied_secret}"; do
    secret_mounts="$(docker exec "${node_name}" find /var/lib/kubelet/pods \
        -path "*/volumes/kubernetes.io~secret/${token_secret}/token" -print)"
    if [[ -z "${secret_mounts}" ]]; then
        echo "node did not expose mounted token ${token_secret} for discovery" >&2
        exit 1
    fi
done

build_peirates_for_kind_node "${root_dir}" "${peirates_binary}" "${node_name}"
docker cp "${peirates_binary}" "${node_name}:/peirates"
docker exec "${node_name}" chmod 0755 /peirates

cat <<INSTRUCTIONS

The disposable ConfigMap scan fixture is ready. Peirates will open in its full
menu on the Kind node. Press Enter when startup credential discovery says
"Press enter to continue". Enter 35 or scan-configmaps, inspect the results,
then press Enter at the next pause to return to the menu. Enter exit when done.
You can run both command forms before exiting.
Peirates may print "Problem with scanln" after a blank Enter; the menu still
continues.

Expected coverage:
  active certificate ${node_identity}: all namespaces complete
  stored token ${namespace}/${allowed_secret}: cluster list forbidden;
    current namespace complete
  stored token ${namespace}/${denied_secret}: cluster list forbidden;
    current namespace incomplete: forbidden

Expected findings, each under ${namespace}/${fixture_map}:
  data:jwt-text       JWT-shaped token
  binaryData:binary-jwt JWT-shaped token
  data:ssh-private-key private key block
  data:aws-session    AWS access key ID
  data:gcp-access     Google OAuth access token candidate
  data:azure-sas      Azure Storage credential candidate

Each finding should be readable by the active certificate and allowed stored
token, never by the denied stored token. ${namespace}/${clean_map} should have
no finding. Credential values and token contents should not appear in output.

The API state and RBAC grants were checked independently before this handoff.
The script will check them again after exit, then delete its owned cluster.
Press Ctrl-C to cancel; cleanup will still run.

INSTRUCTIONS

# Keep stdin and stdout on the operator's terminal; -m would skip the menu.
docker exec -it "${node_name}" /peirates -c

# Validate persisted state independently of the menu output before cleanup.
if [[ "$(kubectl --context "${context}" auth can-i list configmaps --all-namespaces \
    --as="${node_identity}")" != yes ||
    "$(kubectl --context "${context}" auth can-i list configmaps -n "${namespace}" \
    --as="${allowed_identity}")" != yes ||
    "$(kubectl --context "${context}" auth can-i list configmaps --all-namespaces \
    --as="${allowed_identity}")" != no ||
    "$(kubectl --context "${context}" auth can-i list configmaps -n "${namespace}" \
    --as="${denied_identity}")" != no ||
    "$(kubectl --context "${context}" auth can-i list configmaps --all-namespaces \
    --as="${denied_identity}")" != no ]]; then
    echo "ConfigMap RBAC changed during the interactive session" >&2
    exit 1
fi
if [[ "$(kubectl --context "${context}" -n "${namespace}" get configmap "${fixture_map}" \
    -o jsonpath='{.data.jwt-text}')" != "prefix ${jwt_value} suffix" ||
    "$(kubectl --context "${context}" -n "${namespace}" get configmap "${fixture_map}" \
    -o jsonpath='{.binaryData.binary-jwt}')" != "${binary_jwt}" ||
    "$(kubectl --context "${context}" -n "${namespace}" get configmap "${fixture_map}" \
    -o jsonpath='{.data.ssh-private-key}')" != "$(cat "${ssh_key_file}")" ||
    "$(kubectl --context "${context}" -n "${namespace}" get configmap "${fixture_map}" \
    -o jsonpath='{.data.aws-session}')" != "AWS_ACCESS_KEY_ID=${aws_key_id}" ||
    "$(kubectl --context "${context}" -n "${namespace}" get configmap "${fixture_map}" \
    -o jsonpath='{.data.gcp-access}')" != "${gcp_token}" ||
    "$(kubectl --context "${context}" -n "${namespace}" get configmap "${fixture_map}" \
    -o jsonpath='{.data.azure-sas}')" != "${azure_sas}" ||
    "$(kubectl --context "${context}" -n "${namespace}" get configmap "${clean_map}" \
    -o jsonpath='{.data.plain}')" != 'ordinary configuration without credential markers' ]]; then
    echo "ConfigMap fixtures changed during the interactive session" >&2
    exit 1
fi
if [[ "$(kubectl --context "${context}" -n "${namespace}" get pod "${runner_pod}" \
    -o jsonpath='{.status.phase}')" != Running ||
    "$(kubectl --context "${context}" get --raw /readyz)" != ok ]]; then
    echo "fixture pod or API server is unhealthy after the interactive session" >&2
    exit 1
fi
for token_secret in "${allowed_secret}" "${denied_secret}"; do
    if [[ -z "$(kubectl --context "${context}" -n "${namespace}" get secret \
        "${token_secret}" -o jsonpath='{.data.token}')" ||
        -z "$(docker exec "${node_name}" find /var/lib/kubelet/pods \
        -path "*/volumes/kubernetes.io~secret/${token_secret}/token" -print)" ]]; then
        echo "stored token fixture disappeared during the interactive session" >&2
        exit 1
    fi
done

echo "manual ConfigMap scan fixture remained intact; cleaning up ${cluster_name}"
