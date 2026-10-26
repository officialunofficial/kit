#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# One-time setup of the Rust CI for kit on Google Cloud Build. The script only
# runs when a maintainer starts it. No test and no CI step runs it.
#
# The repository must already be linked to a 2nd-generation Cloud Build GitHub
# connection, so no GitHub App is installed here. The script provisions:
#   1. the sccache bucket, with access for the build service account,
#   2. the toolchain image (cloudbuild/Dockerfile.ci) in Artifact Registry,
#   3. the build triggers.
#
# Scope: CI only. The release, the release verification and the macOS test leg
# stay on GitHub Actions. cloudbuild/README.md explains the split.
#
# The script is idempotent. It skips a bucket, an image binding or a trigger
# that exists. It needs an authenticated gcloud. Run it from the repository
# root:
#   PROJECT=<id> bash scripts/setup-cloud-build.sh
#
# Environment:
#   PROJECT                    Google Cloud project. The default is the gcloud
#                              configuration.
#   REGION                     Region of the connection, triggers and registry.
#   CONNECTION, REPO           The Cloud Build connection and repository name.
#   ENABLE_SCHEDULED_TRIGGERS  Set to 1 to add the weekly runs.
set -euo pipefail

PROJECT="${PROJECT:-$(gcloud config get-value project 2>/dev/null || true)}"
: "${PROJECT:?set PROJECT, or run: gcloud config set project <id>}"
REGION="${REGION:-us-east4}"
CONNECTION="${CONNECTION:-github}"
REPO="${REPO:-officialunofficial-kit}"
CACHE_BUCKET="${CACHE_BUCKET:-${PROJECT}-kit-sccache}"
TOOLCHAIN="$(bash "$(dirname "${BASH_SOURCE[0]}")/toolchain-version.sh")"
CI_IMAGE="${CI_IMAGE:-us-east4-docker.pkg.dev/${PROJECT}/docker/kit-ci:rust-${TOOLCHAIN}}"
GAR_REPO="${GAR_REPO:-docker}"

REPO_RES="projects/${PROJECT}/locations/${REGION}/connections/${CONNECTION}/repositories/${REPO}"
PROJ_NUM="$(gcloud projects describe "$PROJECT" --format='value(projectNumber)')"
BUILD_SA="${PROJ_NUM}@cloudbuild.gserviceaccount.com"

echo "Project ${PROJECT} (#${PROJ_NUM}); build service account ${BUILD_SA}"
echo "Repository resource: ${REPO_RES}"

# 1. The sccache bucket and the access of the build service account.
echo "== sccache bucket =="
gcloud storage buckets create "gs://${CACHE_BUCKET}" \
  --project="$PROJECT" --location="$REGION" --uniform-bucket-level-access \
  || echo "  (bucket exists: skipping)"
# Cache objects expire after 30 days. This bounds the cost.
printf '{"rule":[{"action":{"type":"Delete"},"condition":{"age":30}}]}' \
  | gcloud storage buckets update "gs://${CACHE_BUCKET}" --lifecycle-file=/dev/stdin
gcloud storage buckets add-iam-policy-binding "gs://${CACHE_BUCKET}" \
  --member="serviceAccount:${BUILD_SA}" --role="roles/storage.objectAdmin"

# 2. The toolchain image. Build it again when Dockerfile.ci or
# rust/rust-toolchain.toml changes. The build service account needs write
# access to the registry.
echo "== toolchain image (${CI_IMAGE}) =="
gcloud artifacts repositories add-iam-policy-binding "$GAR_REPO" \
  --project="$PROJECT" --location="$REGION" \
  --member="serviceAccount:${BUILD_SA}" --role="roles/artifactregistry.writer" >/dev/null
gcloud builds submit . --project="$PROJECT" --region="$REGION" \
  --config=cloudbuild/builder.yaml --substitutions="_CI_IMAGE=${CI_IMAGE}"

# 3. The triggers. A pull request from an organization collaborator starts a
# build at once. A pull request from an external contributor waits for a
# maintainer comment `/gcbrun`.
COL="COMMENTS_ENABLED_FOR_EXTERNAL_CONTRIBUTORS_ONLY"

# Create a trigger unless one with this name exists.
mk() {
  local name="$1"; shift
  if gcloud builds triggers describe "$name" --project="$PROJECT" --region="$REGION" \
       >/dev/null 2>&1; then
    echo "  (trigger ${name} exists: skipping)"
    return 0
  fi
  gcloud builds triggers create github --project="$PROJECT" --region="$REGION" \
    --repository="$REPO_RES" --name="$name" "$@"
}
mk_pr()   { local n="$1"; shift; mk "$n" --pull-request-pattern='^main$' "$@"; }
mk_push() { local n="$1"; shift; mk "$n" --branch-pattern='^main$' "$@"; }

echo "== triggers =="

# The main suite. No path filter: the writing and path checks read the
# documents too, so a change to a document can fail them. This trigger is the
# required check of the repository.
mk_pr   kit-ci-pr   --build-config=cloudbuild/ci.yaml --comment-control="$COL"
mk_push kit-ci-main --build-config=cloudbuild/ci.yaml

# Third-party notices and the release artifact check. They run only when an
# input that can change the result changes.
SUPPLY_FILES='rust/Cargo.lock','rust/Cargo.toml','rust/crates/**/Cargo.toml','rust/crates/kit-bin/**','rust/about.toml','rust/about.hbs','rust/rust-toolchain.toml','scripts/check-release-artifact-features.sh','scripts/check-publish.sh','scripts/release/**','.github/workflows/release.yml','cloudbuild/supply.yaml'
mk_pr   kit-supply-pr   --build-config=cloudbuild/supply.yaml \
        --comment-control="$COL" --included-files="$SUPPLY_FILES"
mk_push kit-supply-main --build-config=cloudbuild/supply.yaml \
        --included-files="$SUPPLY_FILES"

# The latest-release probe of the Connect stack, on changes to the manifests.
CONNECT_FILES='**/Cargo.toml','**/Cargo.lock','scripts/check-connect-latest.sh','cloudbuild/connect-latest.yaml'
mk_pr   kit-connect-pr --build-config=cloudbuild/connect-latest.yaml \
        --comment-control="$COL" --included-files="$CONNECT_FILES"

# Weekly runs (opt in). A new advisory can match a dependency tree that did not
# change, and a new Connect release can break an unchanged tree. Each run has a
# manual trigger and a Cloud Scheduler job that starts it. Times are UTC.
mk_weekly() {
  local name="$1" config="$2" cron="$3"
  if gcloud builds triggers describe "$name" --project="$PROJECT" --region="$REGION" \
       >/dev/null 2>&1; then
    echo "  (trigger ${name} exists: skipping)"
  else
    gcloud builds triggers create manual --project="$PROJECT" --region="$REGION" \
      --repository="$REPO_RES" --name="$name" --branch=main --build-config="$config"
  fi
  if gcloud scheduler jobs describe "$name" --project="$PROJECT" --location="$REGION" \
       >/dev/null 2>&1; then
    echo "  (scheduler job ${name} exists: skipping)"
    return 0
  fi
  gcloud scheduler jobs create http "$name" --project="$PROJECT" --location="$REGION" \
    --schedule="$cron" --time-zone=UTC --http-method=POST \
    --uri="https://cloudbuild.googleapis.com/v1/projects/${PROJECT}/locations/${REGION}/triggers/${name}:run" \
    --message-body='{"source":{"branchName":"main"}}' \
    --oauth-service-account-email="$BUILD_SA"
}
if [ "${ENABLE_SCHEDULED_TRIGGERS:-0}" = "1" ]; then
  echo "== weekly triggers =="
  mk_weekly kit-ci-weekly      cloudbuild/ci.yaml              '0 6 * * 1'
  mk_weekly kit-connect-weekly cloudbuild/connect-latest.yaml  '23 5 * * 1'
fi

echo "Done. Triggers:"
gcloud builds triggers list --project="$PROJECT" --region="$REGION" \
  --format='table(name,filename)'
