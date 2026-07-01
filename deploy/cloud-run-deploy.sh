#!/usr/bin/env bash
# ============================================================
# AgentGuard — Cloud Run deploy script
# Builds the Go proxy in backend/ and deploys it to Google
# Cloud Run's free tier (scales to zero when idle).
#
# Usage:
#   ./deploy/cloud-run-deploy.sh
#
# Prereqs:
#   - gcloud CLI installed and authenticated (gcloud auth login)
#   - A GCP project created with billing enabled (free tier still
#     requires a billing account on file, you just won't be charged
#     within the free tier limits)
#   - Environment variables exported before running (see below)
# ============================================================

set -euo pipefail

# --- Configuration — edit these for your project ---
PROJECT_ID="${AGENTGUARD_GCP_PROJECT:-your-gcp-project-id}"
REGION="${AGENTGUARD_GCP_REGION:-asia-south1}"
SERVICE_NAME="agentguard-proxy"
IMAGE_NAME="gcr.io/${PROJECT_ID}/${SERVICE_NAME}"
BACKEND_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../backend" && pwd)"

echo "[1/5] Setting active gcloud project to ${PROJECT_ID}..."
gcloud config set project "${PROJECT_ID}"

echo "[2/5] Enabling required GCP APIs (safe to re-run)..."
gcloud services enable \
  run.googleapis.com \
  cloudbuild.googleapis.com \
  containerregistry.googleapis.com

echo "[3/5] Building container image from ${BACKEND_DIR}..."
gcloud builds submit "${BACKEND_DIR}" --tag "${IMAGE_NAME}"

# --- Alternative: build locally with Docker instead of Cloud Build ---
# docker build -t "${IMAGE_NAME}" "${BACKEND_DIR}"
# docker push "${IMAGE_NAME}"

echo "[4/5] Deploying to Cloud Run..."
# These env var names match internal/database/database.go and
# internal/breaker/breaker.go exactly:
#   SUPABASE_URL, SUPABASE_KEY           -> database.go
#   UPSTASH_REDIS_REST_URL/_TOKEN        -> breaker.go
# Export them in your shell before running this script, e.g.:
#   export SUPABASE_URL="https://xxxx.supabase.co"
#   export SUPABASE_KEY="your-service-role-key"
#   export UPSTASH_REDIS_REST_URL="https://xxxx.upstash.io"
#   export UPSTASH_REDIS_REST_TOKEN="your-upstash-token"
gcloud run deploy "${SERVICE_NAME}" \
  --image "${IMAGE_NAME}" \
  --region "${REGION}" \
  --platform managed \
  --allow-unauthenticated \
  --port 8080 \
  --min-instances 0 \
  --max-instances 10 \
  --memory 256Mi \
  --cpu 1 \
  --timeout 30 \
  --set-env-vars "SUPABASE_URL=${SUPABASE_URL:-},SUPABASE_KEY=${SUPABASE_KEY:-},UPSTASH_REDIS_REST_URL=${UPSTASH_REDIS_REST_URL:-},UPSTASH_REDIS_REST_TOKEN=${UPSTASH_REDIS_REST_TOKEN:-}"

echo "[5/5] Deployment complete. Fetching service URL..."
SERVICE_URL="$(gcloud run services describe "${SERVICE_NAME}" \
  --region "${REGION}" \
  --format 'value(status.url)')"

echo ""
echo "AgentGuard proxy is live at: ${SERVICE_URL}"
echo "MCP endpoint:                ${SERVICE_URL}/mcp"
echo "Dashboard data endpoints:     ${SERVICE_URL}/logs/recent  and  ${SERVICE_URL}/policy"
echo ""
echo "Point your frontend at this URL by adding, before terminal.js/app.html load:"
echo "  <script>window.AGENTGUARD_API_BASE = \"${SERVICE_URL}\";</script>"