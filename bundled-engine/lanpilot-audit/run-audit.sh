#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROGRESS_FILE="${LANPILOT_PROGRESS_FILE:-$HOME/.lanpilot-audit/progress.json}"
LOG_FILE="${LANPILOT_LOG_FILE:-$HOME/.lanpilot-audit/latest-run.log}"
STEPS=(
  "01-init-lab.sh"
  "02-baseline.sh"
  "03-passive-assets.sh"
  "04-client-isolation.sh"
  "05-common-services.sh"
  "06-smb-posture.sh"
  "07-gateway-posture.sh"
  "08-build-report.sh"
  "09-local-network-config.sh"
  "10-mdns-observation.sh"
  "11-web-tls-baseline.sh"
  "12-build-enhanced-governance-report.py"
  "13-build-formats.py"
)

mkdir -p "$(dirname "${PROGRESS_FILE}")" "$(dirname "${LOG_FILE}")"
: > "${LOG_FILE}"

json_escape() {
  printf '%s' "${1:-}" | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/\\t/g'
}

write_progress() {
  local state="$1" current="$2" total="$3" step="$4" message="$5"
  local lab_dir=""
  if [[ -L "$HOME/lanpilot-audit-latest" ]]; then
    lab_dir="$(readlink "$HOME/lanpilot-audit-latest")"
  fi
  printf '{"state":"%s","current":%s,"total":%s,"step":"%s","message":"%s","lab_dir":"%s","updated_at":"%s"}\n' \
    "$(json_escape "${state}")" "${current}" "${total}" "$(json_escape "${step}")" \
    "$(json_escape "${message}")" "$(json_escape "${lab_dir}")" "$(date '+%Y-%m-%d %H:%M:%S %Z')" \
    > "${PROGRESS_FILE}"
}

run_step() {
  local index="$1" script="$2"
  local total="${#STEPS[@]}"
  write_progress "running" "${index}" "${total}" "${script}" "Running ${script}"
  printf '\n[%s] Starting %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "${script}" | tee -a "${LOG_FILE}"
  if [[ "${script}" == *.py ]]; then
    python3 "${SCRIPT_DIR}/${script}" 2>&1 | tee -a "${LOG_FILE}"
  else
    "${SCRIPT_DIR}/${script}" 2>&1 | tee -a "${LOG_FILE}"
  fi
}

on_error() {
  local status=$?
  write_progress "failed" "${CURRENT_STEP:-0}" "${#STEPS[@]}" "${CURRENT_SCRIPT:-unknown}" "Run failed. Review ${LOG_FILE}"
  exit "${status}"
}
trap on_error ERR

write_progress "running" "0" "${#STEPS[@]}" "starting" "Starting authorized governance audit"
for i in "${!STEPS[@]}"; do
  CURRENT_STEP=$((i + 1))
  CURRENT_SCRIPT="${STEPS[$i]}"
  run_step "${CURRENT_STEP}" "${CURRENT_SCRIPT}"
done
write_progress "completed" "${#STEPS[@]}" "${#STEPS[@]}" "completed" "Audit and reports completed"
printf '\nLANPilot Audit completed. Latest results: %s\n' "$HOME/lanpilot-audit-latest" | tee -a "${LOG_FILE}"
