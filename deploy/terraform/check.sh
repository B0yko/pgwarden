#!/usr/bin/env bash
# Runs all five Terraform checks (fmt, validate, test, tflint, trivy config)
# entirely through pinned Docker images. Never authenticates to any cloud:
# no gcloud, no terraform plan/apply, empty HOME/CLOUDSDK_CONFIG inside
# every container, no GOOGLE_* variables passed through.
#
# Usage: deploy/terraform/check.sh
# Run from anywhere; paths below are resolved relative to this script.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

DOCKER="${DOCKER_BIN:-$HOME/.local/bin/docker}"

TERRAFORM_IMAGE="hashicorp/terraform@sha256:985cdc6c1d9b0a65b83377f666efd2f740b47f02ac55be1ced3d18f7d3b0e829" # 1.16.4
TFLINT_IMAGE="ghcr.io/terraform-linters/tflint@sha256:1c595f42d794c32c45a6ea8b58655fd66433d4ca3b1bc631c574a48d120bd19f"   # v0.64.0
TRIVY_IMAGE="aquasec/trivy@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969"                     # 0.74.0

BUILDCACHE_DIR="$SCRIPT_DIR/../../_buildcache"
mkdir -p "$BUILDCACHE_DIR/tflint-home" "$BUILDCACHE_DIR/trivy-home"

tf() {
  "$DOCKER" run --rm --name "pgwarden-tf-check-$$-$RANDOM" \
    -v "$SCRIPT_DIR":/workspace -w /workspace \
    -e HOME=/tmp/home -e CLOUDSDK_CONFIG=/tmp/gcloud \
    "$TERRAFORM_IMAGE" "$@"
}

echo "==> terraform fmt -check"
tf fmt -check -recursive -diff /workspace

echo "==> terraform init -backend=false (module)"
tf -chdir=gcp-cloud-run init -backend=false -input=false >/dev/null

echo "==> terraform validate (module)"
tf -chdir=gcp-cloud-run validate

echo "==> terraform init -backend=false (example)"
tf -chdir=examples/minimal init -backend=false -input=false >/dev/null

echo "==> terraform validate (example)"
tf -chdir=examples/minimal validate

echo "==> terraform test (mock providers, no credentials)"
tf -chdir=gcp-cloud-run test

echo "==> tflint --init"
"$DOCKER" run --rm --name "pgwarden-tf-check-tflint-init-$$" \
  -v "$SCRIPT_DIR":/workspace -w /workspace \
  -v "$BUILDCACHE_DIR/tflint-home":/tmp/home \
  -e HOME=/tmp/home \
  "$TFLINT_IMAGE" --init

echo "==> tflint (module)"
"$DOCKER" run --rm --name "pgwarden-tf-check-tflint-mod-$$" \
  -v "$SCRIPT_DIR":/workspace -w /workspace/gcp-cloud-run \
  -v "$BUILDCACHE_DIR/tflint-home":/tmp/home \
  -e HOME=/tmp/home \
  "$TFLINT_IMAGE" --config /workspace/.tflint.hcl

echo "==> tflint (example)"
"$DOCKER" run --rm --name "pgwarden-tf-check-tflint-ex-$$" \
  -v "$SCRIPT_DIR":/workspace -w /workspace/examples/minimal \
  -v "$BUILDCACHE_DIR/tflint-home":/tmp/home \
  -e HOME=/tmp/home \
  "$TFLINT_IMAGE" --config /workspace/.tflint.hcl

echo "==> trivy config"
"$DOCKER" run --rm --name "pgwarden-tf-check-trivy-$$" \
  -v "$SCRIPT_DIR":/workspace -w /workspace \
  -v "$BUILDCACHE_DIR/trivy-home":/tmp/home \
  -e HOME=/tmp/home \
  "$TRIVY_IMAGE" config --exit-code 1 --severity LOW,MEDIUM,HIGH,CRITICAL \
    --ignorefile /workspace/.trivyignore /workspace

echo "==> all checks passed"
