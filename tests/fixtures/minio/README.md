# CI S3 fixture

The latest public MinIO release is [RELEASE.2025-10-15T17-29-55Z](https://github.com/minio/minio/releases/tag/RELEASE.2025-10-15T17-29-55Z), which fixes a session-policy bypass. Its release instructions require building the container from source. The old Bitnami Legacy and Quay images do not contain this release.

This test-only image builds the exact upstream server commit and latest public [mc release](https://github.com/minio/mc/releases/tag/RELEASE.2025-08-13T08-35-41Z) with Go 1.27.1. Both source archives and all base images are pinned by digest. The upstream Go module graphs stay at those releases, with `-mod=readonly`; this fixture is not a new fork of MinIO. Upstream AGPL license files are retained in the image.

The shared-state and coverage suites use the same fixture. Existing loopback port binding, task container cleanup, bucket setup and S3 tests remain in place. The fixture has no role in the product runtime.
