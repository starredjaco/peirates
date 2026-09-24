# Scan ConfigMaps for misplaced credentials

## Menu entry

- **Menu item:** `35`
- **Canonical command:** `scan-configmaps`
- **Maturity:** Read-only credential discovery

## Purpose

Find values that appear to be credentials in Kubernetes ConfigMaps, where
readers may have broader access than they have to Secrets. Findings identify
locations for review; pattern matching does not prove that a credential is
valid, active, or usable.

## Prerequisites and authorization

Peirates needs a Kubernetes API connection and at least one usable active or
stored identity. The scanner tries the active connection, each stored service
account token, and each stored client certificate. A principal needs `list`
permission on ConfigMaps to read them. Each request uses that principal's own
credentials and the applicable API server and TLS settings. Cluster-wide
listing requires permission across namespaces; when forbidden, the scanner
tries the current namespace and reports the narrower coverage. A denial for
one identity does not prevent attempts with the others.

## Usage

Select `35` or `scan-configmaps` from the full menu, or invoke it once:

```sh
peirates -m scan-configmaps
```

The command needs no additional input. It does not change the active identity
or stored credentials.

## What it does

The scanner inspects the `data` and `binaryData` values in readable
ConfigMaps. It searches inside values for `eyJ` and validates the structure of
JWT-shaped candidates. Other detectors recognize SSH or PEM private-key blocks,
AWS `AKIA` and `ASIA` access-key IDs, Google `ya29.` access-token candidates
and service-account key JSON, and Azure Storage SAS or connection strings and
client-secret settings JSON. JWT decoding is only a shape check; it does not
verify a signature or expiration. An AWS `ASIA` key ID is evidence of a
temporary access-key ID, not proof that a complete STS credential set is
present.

## Expected output

Findings identify the namespace, ConfigMap, data key, detector, and identities
that could read the location. Credential values are withheld. Multiple
identities reading one location appear together rather than as repeated
credential text. The command reports incomplete coverage from permission
denials, failed requests, or scan limits. Treat even location metadata as
sensitive when saving or sharing output.

Per identity, the scanner stops after 200 pages or 2,000 ConfigMaps. It also
limits each API response to 16 MiB and the combined report to 5,000 findings.
Reaching a limit is reported as incomplete coverage.

## Side effects and cleanup

The command only lists ConfigMaps. It does not read Secrets, test discovered
credentials against cloud services, create or edit Kubernetes objects, or
write credential values to an output file. No cluster cleanup is required.

## Failure modes and limitations

- A principal with only namespace-scoped `list` permission can see only the
  selected namespace through the fallback.
- Network, TLS, authentication, authorization, pagination, or size failures
  leave coverage incomplete; review the reported per-identity status.
- Encoded, encrypted, split, or unfamiliar credential formats can be missed.
  Text that matches a known pattern can also be a false positive.
- A ConfigMap may change during a scan. A finding describes what was returned
  by the API during that run, not a stable inventory.

## Implementation and tests

- [Scanner](../../internal/modules/configmapscan)
- [Menu registration](../../internal/app/module_registry.go)
- [Application command tests](../../internal/app/module_commands_test.go)
