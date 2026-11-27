# GPU driver installer regional admission

## Contract

One GPU driver installation is admitted by the triple:

1. the component source (registry host, repository, and tag of the
   `cos_gpu_installer` image);
2. the pinned trust root (`InstallerDigest`, plus the pinned Google root
   certificates used for the pull);
3. the node's target region (`LaunchSpec.Region` from the metadata server).

`launcher/internal/gpu.admitInstallerComponents` evaluates that triple as one
admission conclusion before anything is pulled or installed into the trusted
boot chain:

- The installer source is derived from the target region, so a node never
  pulls installer components from the wrong region
  (`us-*` -> `us.gcr.io`, `europe-*` -> `eu.gcr.io`, `asia-*` -> `asia.gcr.io`).
- A source host that is not the approved regional host for the target region
  is rejected.
- A repository or tag other than the approved installer coordinates is
  rejected.
- A pinned digest that is malformed, empty, or different from
  `InstallerDigest` is rejected; the trust root is never region-agnostic.
- A target region with no approved installer source fails closed; there is no
  fallback source.

On success the admission returns the digest-pinned pull reference
(`host/repository:tag@digest`), so containerd rejects any other manifest
before downloading layers. After the pull, `verifyInstallerImageDigest`
re-checks the fetched image against the same pinned digest, and
`verifyDriverDigest` admits the downloaded driver runfile only under its own
pinned digest, so every installed component is covered by the same
source/trust-root/region conclusion.

## Compatibility

Nodes in `us-*`, `europe-*`, and `asia-*` regions pull the same approved
installer image from their regional Google Container Registry host. Nodes in
regions without an approved installer source can no longer install GPU
drivers at runtime; previously they silently pulled components from the
hardcoded `us.gcr.io` source.

## Regression evidence

`launcher/internal/gpu/installer_admission_test.go` covers the region-to-host
mapping, the agreeing triple, wrong-region sources, non-Google sources,
unapproved repositories and tags, stale/malformed/empty trust roots, empty
and unmapped target regions, and digest pinning of the admitted pull
reference. `driverinstaller_test.go` exercises the admitted reference through
the registry resolver and confirms the manifest is requested by digest.
