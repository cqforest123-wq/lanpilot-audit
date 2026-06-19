use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs,
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicBool, Ordering},
    time::{Instant, UNIX_EPOCH},
};
use tauri::{Emitter, Manager};
use zip::write::SimpleFileOptions;

const ENGINE_DIRECTORY: &str = "lanpilot-audit";
const APP_SUPPORT_DIRECTORY: &str = "Library/Application Support/LANPilot Audit";
const BUNDLED_ENGINE_VERSION: &str = "1.3.0";
const LATEST_LAB_DIRECTORY: &str = "lanpilot-audit-latest";
const EXPORT_DIRECTORY: &str = "Desktop/LANPilot-Audit-Exports";
const AUDIT_PATH: &str = "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin";

const ENGINE_SCRIPTS: [(&str, &str); 13] = [
    ("init_lab", "01-init-lab.sh"),
    ("baseline", "02-baseline.sh"),
    ("passive_assets", "03-passive-assets.sh"),
    ("client_isolation", "04-client-isolation.sh"),
    ("common_services", "05-common-services.sh"),
    ("smb_posture", "06-smb-posture.sh"),
    ("gateway_posture", "07-gateway-posture.sh"),
    ("build_report", "08-build-report.sh"),
    ("local_network_config", "09-local-network-config.sh"),
    ("mdns_observation", "10-mdns-observation.sh"),
    ("web_tls_baseline", "11-web-tls-baseline.sh"),
    ("build_enhanced_governance_report", "12-build-enhanced-governance-report.py"),
    ("build_formats", "13-build-formats.py"),
];

#[derive(Clone, Copy, serde::Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum AuditStep {
    InitLab,
    Baseline,
    PassiveAssets,
    ClientIsolation,
    CommonServices,
    SmbPosture,
    GatewayPosture,
    BuildReport,
    LocalNetworkConfig,
    MdnsObservation,
    WebTlsBaseline,
    BuildEnhancedGovernanceReport,
    BuildFormats,
}

impl AuditStep {
    fn id(self) -> &'static str {
        match self {
            Self::InitLab => "init_lab",
            Self::Baseline => "baseline",
            Self::PassiveAssets => "passive_assets",
            Self::ClientIsolation => "client_isolation",
            Self::CommonServices => "common_services",
            Self::SmbPosture => "smb_posture",
            Self::GatewayPosture => "gateway_posture",
            Self::BuildReport => "build_report",
            Self::LocalNetworkConfig => "local_network_config",
            Self::MdnsObservation => "mdns_observation",
            Self::WebTlsBaseline => "web_tls_baseline",
            Self::BuildEnhancedGovernanceReport => "build_enhanced_governance_report",
            Self::BuildFormats => "build_formats",
        }
    }

    fn script_name(self) -> &'static str {
        match self {
            Self::InitLab => "01-init-lab.sh",
            Self::Baseline => "02-baseline.sh",
            Self::PassiveAssets => "03-passive-assets.sh",
            Self::ClientIsolation => "04-client-isolation.sh",
            Self::CommonServices => "05-common-services.sh",
            Self::SmbPosture => "06-smb-posture.sh",
            Self::GatewayPosture => "07-gateway-posture.sh",
            Self::BuildReport => "08-build-report.sh",
            Self::LocalNetworkConfig => "09-local-network-config.sh",
            Self::MdnsObservation => "10-mdns-observation.sh",
            Self::WebTlsBaseline => "11-web-tls-baseline.sh",
            Self::BuildEnhancedGovernanceReport => "12-build-enhanced-governance-report.py",
            Self::BuildFormats => "13-build-formats.py",
        }
    }

    fn requires_nmap(self) -> bool {
        matches!(
            self,
            Self::CommonServices | Self::SmbPosture | Self::GatewayPosture
        )
    }
}

const AUDIT_STEPS: [AuditStep; 13] = [
    AuditStep::InitLab,
    AuditStep::Baseline,
    AuditStep::PassiveAssets,
    AuditStep::ClientIsolation,
    AuditStep::CommonServices,
    AuditStep::SmbPosture,
    AuditStep::GatewayPosture,
    AuditStep::BuildReport,
    AuditStep::LocalNetworkConfig,
    AuditStep::MdnsObservation,
    AuditStep::WebTlsBaseline,
    AuditStep::BuildEnhancedGovernanceReport,
    AuditStep::BuildFormats,
];

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditInterface {
    name: String,
    ipv4: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScriptStatus {
    step_id: &'static str,
    script_name: &'static str,
    exists: bool,
    executable: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EngineStatus {
    engine_path: String,
    engine_found: bool,
    scripts_ready: bool,
    missing_scripts: Vec<String>,
    nmap_available: bool,
    latest_lab_exists: bool,
    warnings: Vec<String>,
    scripts: Vec<ScriptStatus>,
    engine_version: Option<String>,
    bundled_engine_version: &'static str,
    update_available: bool,
    development_fallback: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditStepResult {
    step_id: String,
    script_name: String,
    success: bool,
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
    duration_ms: u128,
    skipped: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FullAuditResult {
    success: bool,
    steps: Vec<AuditStepResult>,
    failed_step_id: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditStepEvent {
    step_id: String,
    status: &'static str,
    result: Option<AuditStepResult>,
    error: Option<String>,
}

#[derive(Clone, serde::Deserialize, Serialize)]
struct RiskFinding {
    severity: String,
    asset: String,
    category: String,
    finding: String,
    recommended_action: String,
    status: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReportSummary {
    high_count: Option<usize>,
    medium_count: Option<usize>,
    low_count: Option<usize>,
    reachable_clients: Option<usize>,
    unreachable_clients: Option<usize>,
    open_service_hosts: Option<usize>,
    gateway_posture_status: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LatestReport {
    generated_at: Option<u64>,
    lab_directory: String,
    executive_summary: Option<String>,
    technical_report: Option<String>,
    risk_register: Option<String>,
    remediation_roadmap: Option<String>,
    evidence_index: Option<String>,
    asset_inventory: Option<String>,
    asset_inventory_summary: Option<String>,
    service_exposure_matrix: Option<String>,
    service_exposure_summary: Option<String>,
    local_network_config: Option<String>,
    mdns_services: Option<String>,
    web_baseline: Option<String>,
    tls_certificates: Option<String>,
    snapshot_diff: Option<String>,
    remediation_tracking: Option<String>,
    governance_summary: Option<String>,
    missing_files: Vec<String>,
    findings: Vec<RiskFinding>,
    summary: ReportSummary,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExportResult {
    zip_path: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NetworkReliabilityRun {
    summary: serde_json::Value,
    evidence: serde_json::Value,
    report_markdown: String,
    support_bundle_path: String,
    output_directory: String,
}

#[derive(Clone)]
struct CommandCapture {
    label: String,
    command: String,
    args: Vec<String>,
    success: bool,
    stdout: String,
    stderr: String,
}

#[derive(Clone, serde::Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct RemediationRecord {
    finding_id: String,
    owner: String,
    due_date: String,
    status: String,
    notes: String,
    priority: String,
    business_justification: String,
}

#[derive(Clone, serde::Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct RemediationTicket {
    id: String,
    finding_fingerprint: String,
    severity: String,
    asset: String,
    category: String,
    localized_finding: String,
    localized_recommended_action: String,
    owner: String,
    due_date: String,
    priority: String,
    status: String,
    business_justification: String,
    manual_steps: Vec<String>,
    validation_steps: Vec<String>,
    rollback_considerations: Vec<String>,
    evidence_references: Vec<String>,
    notes: String,
}

#[derive(Clone, serde::Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct RemediationPack {
    id: String,
    generated_at: String,
    lab_directory: String,
    language: String,
    risk_summary: std::collections::HashMap<String, usize>,
    findings: Vec<RiskFinding>,
    tickets: Vec<RemediationTicket>,
    verification_plan: Vec<String>,
    acceptance_records: Vec<serde_json::Value>,
}

#[derive(Default)]
struct AuditExecutionState {
    running: AtomicBool,
    authorized: AtomicBool,
}

impl AuditExecutionState {
    fn try_start(&self) -> Result<AuditExecutionGuard<'_>, String> {
        self.running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| AuditExecutionGuard { state: self })
            .map_err(|_| "Another audit step is already running.".to_string())
    }

    fn authorize(&self) {
        self.authorized.store(true, Ordering::Release);
    }

    fn consume_authorization(&self) -> Result<(), String> {
        self.authorized
            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| "Audit authorization is required before running a real check.".to_string())
    }
}

struct AuditExecutionGuard<'a> {
    state: &'a AuditExecutionState,
}

impl Drop for AuditExecutionGuard<'_> {
    fn drop(&mut self) {
        self.state.running.store(false, Ordering::Release);
    }
}

fn home_path() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "Unable to determine the current user's home directory.".to_string())
}

fn engine_path() -> Result<PathBuf, String> {
    Ok(home_path()?
        .join(APP_SUPPORT_DIRECTORY)
        .join(ENGINE_DIRECTORY))
}

fn development_engine_path() -> Result<PathBuf, String> {
    Ok(home_path()?.join(ENGINE_DIRECTORY))
}

fn active_engine_path() -> Result<(PathBuf, bool), String> {
    let installed = engine_path()?;
    if is_regular_directory(&installed) {
        return Ok((installed, false));
    }
    let fallback = development_engine_path()?;
    if cfg!(debug_assertions) && is_regular_directory(&fallback) {
        return Ok((fallback, true));
    }
    Ok((installed, false))
}

fn bundled_engine_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    if cfg!(debug_assertions) {
        let development = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("bundled-engine")
            .join(ENGINE_DIRECTORY);
        if is_regular_directory(&development) {
            return Ok(development);
        }
    }
    app.path()
        .resource_dir()
        .map(|path| path.join("bundled-engine").join(ENGINE_DIRECTORY))
        .map_err(|error| format!("Unable to locate bundled audit engine: {error}"))
}

fn engine_version(path: &Path) -> Option<String> {
    fs::read_to_string(path.join("VERSION"))
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn latest_lab_path() -> Result<PathBuf, String> {
    Ok(home_path()?.join(LATEST_LAB_DIRECTORY))
}

fn export_folder_path() -> Result<PathBuf, String> {
    Ok(home_path()?.join(EXPORT_DIRECTORY))
}

fn command_available(command_name: &str) -> bool {
    AUDIT_PATH.split(':').map(Path::new).any(|directory| {
        fs::metadata(directory.join(command_name))
            .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    })
}

fn is_executable(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| {
            metadata.file_type().is_file() && metadata.permissions().mode() & 0o111 != 0
        })
        .unwrap_or(false)
}

fn is_regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_file())
        .unwrap_or(false)
}

fn is_regular_directory(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_dir())
        .unwrap_or(false)
}

fn collect_engine_files(
    root: &Path,
    directory: &Path,
    files: &mut HashSet<String>,
) -> Result<(), String> {
    for entry in fs::read_dir(directory).map_err(|error| {
        format!(
            "Unable to read engine directory {}: {error}",
            directory.display()
        )
    })? {
        let entry = entry.map_err(|error| format!("Unable to read engine entry: {error}"))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            format!("Unable to inspect engine entry {}: {error}", path.display())
        })?;
        if metadata.file_type().is_symlink() {
            return Err("Audit engine contains an unsafe symbolic link.".to_string());
        }
        if metadata.file_type().is_dir() {
            collect_engine_files(root, &path, files)?;
        } else if metadata.file_type().is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|error| format!("Unable to resolve engine file path: {error}"))?
                .to_string_lossy()
                .replace('\\', "/");
            if relative != "ENGINE_SHA256SUMS.txt" {
                files.insert(relative);
            }
        }
    }
    Ok(())
}

fn verify_engine_manifest(root: &Path) -> Result<(), String> {
    let manifest_path = root.join("ENGINE_SHA256SUMS.txt");
    let manifest = read_required_file(manifest_path)?;
    let mut expected_files = HashSet::new();
    for line in manifest.lines().filter(|line| !line.trim().is_empty()) {
        let (expected_hash, relative) = line
            .split_once("  ")
            .ok_or_else(|| "Audit engine manifest contains an invalid line.".to_string())?;
        let relative_path = Path::new(relative);
        if relative_path.is_absolute()
            || relative_path
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err("Audit engine manifest contains an unsafe path.".to_string());
        }
        if !expected_files.insert(relative.to_string()) {
            return Err("Audit engine manifest contains a duplicate path.".to_string());
        }
        let file_path = root.join(relative_path);
        if !is_regular_file(&file_path) {
            return Err(format!("Audit engine manifest file is missing: {relative}"));
        }
        let mut file = fs::File::open(&file_path)
            .map_err(|error| format!("Unable to read engine file {relative}: {error}"))?;
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 8192];
        loop {
            let count = file
                .read(&mut buffer)
                .map_err(|error| format!("Unable to hash engine file {relative}: {error}"))?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        let actual_hash = format!("{:x}", hasher.finalize());
        if actual_hash != expected_hash {
            return Err(format!("Audit engine integrity check failed: {relative}"));
        }
    }
    let mut actual_files = HashSet::new();
    collect_engine_files(root, root, &mut actual_files)?;
    if actual_files != expected_files {
        return Err(
            "Audit engine contains files not represented by its integrity manifest.".to_string(),
        );
    }
    Ok(())
}

#[tauri::command]
fn check_engine() -> Result<EngineStatus, String> {
    let (path, development_fallback) = active_engine_path()?;
    let engine_found = is_regular_directory(&path);
    let scripts = ENGINE_SCRIPTS
        .iter()
        .map(|(step_id, script_name)| {
            let script_path = path.join(script_name);
            ScriptStatus {
                step_id,
                script_name,
                exists: is_regular_file(&script_path),
                executable: is_executable(&script_path),
            }
        })
        .collect::<Vec<_>>();
    let missing_scripts = scripts
        .iter()
        .filter(|script| !script.exists || !script.executable)
        .map(|script| script.script_name.to_string())
        .collect::<Vec<_>>();
    let manifest_valid = engine_found && verify_engine_manifest(&path).is_ok();
    let scripts_ready = engine_found
        && manifest_valid
        && scripts
            .iter()
            .all(|script| script.exists && script.executable);
    let nmap_available = command_available("nmap");
    let latest_lab_exists = latest_lab_path()?.exists();
    let engine_version = engine_version(&path);
    let update_available = engine_version.as_deref() != Some(BUNDLED_ENGINE_VERSION);
    let mut warnings = Vec::new();
    if !engine_found {
        warnings.push("Local audit engine directory was not found.".to_string());
    }
    if !scripts_ready {
        warnings
            .push("One or more approved audit scripts are missing or not executable.".to_string());
    }
    if !nmap_available {
        warnings.push("nmap is not available on the fixed audit PATH.".to_string());
    }
    if !latest_lab_exists {
        warnings.push("No latest audit lab is available yet.".to_string());
    }
    if development_fallback {
        warnings.push("Using the development engine fallback.".to_string());
    }
    if engine_found && update_available {
        warnings.push("A bundled engine update is available.".to_string());
    }
    if engine_found && !manifest_valid {
        warnings.push("The installed engine failed its integrity check.".to_string());
    }

    Ok(EngineStatus {
        engine_path: path.display().to_string(),
        engine_found,
        scripts_ready,
        missing_scripts,
        nmap_available,
        latest_lab_exists,
        warnings,
        scripts,
        engine_version,
        bundled_engine_version: BUNDLED_ENGINE_VERSION,
        update_available,
        development_fallback,
    })
}

fn validate_audit_interface(value: &str) -> Result<String, String> {
    let valid_name = !value.is_empty()
        && value.len() <= 16
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric());
    if !valid_name {
        return Err("A valid local audit interface is required.".to_string());
    }
    let output = Command::new("/sbin/ifconfig")
        .arg(value)
        .output()
        .map_err(|error| format!("Unable to inspect audit interface: {error}"))?;
    if !output.status.success() {
        return Err("The selected audit interface is not available.".to_string());
    }
    let details = String::from_utf8_lossy(&output.stdout);
    if !details
        .lines()
        .any(|line| line.trim_start().starts_with("inet "))
    {
        return Err("The selected audit interface has no IPv4 address.".to_string());
    }
    Ok(value.to_string())
}

#[tauri::command]
fn list_audit_interfaces() -> Result<Vec<AuditInterface>, String> {
    let output = Command::new("/sbin/ifconfig")
        .arg("-l")
        .output()
        .map_err(|error| format!("Unable to list network interfaces: {error}"))?;
    if !output.status.success() {
        return Err("Unable to list network interfaces.".to_string());
    }
    let mut interfaces = Vec::new();
    for name in String::from_utf8_lossy(&output.stdout).split_whitespace() {
        if name.starts_with("lo")
            || name.starts_with("utun")
            || name.starts_with("awdl")
            || name.starts_with("llw")
            || name.starts_with("bridge")
        {
            continue;
        }
        if let Ok(validated) = validate_audit_interface(name) {
            let details = Command::new("/sbin/ifconfig")
                .arg(&validated)
                .output()
                .map_err(|error| format!("Unable to inspect audit interface: {error}"))?;
            let ipv4 = String::from_utf8_lossy(&details.stdout)
                .lines()
                .find_map(|line| {
                    let fields: Vec<_> = line.split_whitespace().collect();
                    (fields.first() == Some(&"inet") && fields.len() > 1)
                        .then(|| fields[1].to_string())
                })
                .unwrap_or_default();
            interfaces.push(AuditInterface {
                name: validated,
                ipv4,
            });
        }
    }
    Ok(interfaces)
}

fn execute_audit_step(
    step_id: AuditStep,
    audit_interface: &str,
) -> Result<AuditStepResult, String> {
    let started = Instant::now();
    let home = home_path()?;
    let (engine, _) = active_engine_path()?;
    if !is_regular_directory(&engine) {
        return Err(format!(
            "Audit engine directory does not exist: {}",
            engine.display()
        ));
    }
    verify_engine_manifest(&engine)?;

    let script_name = step_id.script_name();
    let script_path = engine.join(script_name);
    if !is_regular_file(&script_path) {
        return Err(format!(
            "Audit script does not exist: {}",
            script_path.display()
        ));
    }
    if !is_executable(&script_path) {
        return Err(format!(
            "Audit script is not executable: {}",
            script_path.display()
        ));
    }

    // The executable and its environment are fixed here; no frontend value is
    // interpreted as a command, argument, path, or environment variable.
    let mut command = Command::new(&script_path);
    command
        .current_dir(&engine)
        .env_clear()
        .env("HOME", home)
        .env("PATH", AUDIT_PATH);
    command.env("LANPILOT_INTERFACE", audit_interface);

    let output = command
        .output()
        .map_err(|error| format!("Failed to run {script_name}: {error}"))?;

    Ok(AuditStepResult {
        step_id: step_id.id().to_string(),
        script_name: script_name.to_string(),
        success: output.status.success(),
        exit_code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        duration_ms: started.elapsed().as_millis(),
        skipped: false,
    })
}

fn execute_limited_step(step: AuditStep, audit_interface: &str) -> Result<AuditStepResult, String> {
    let mut result = execute_audit_step(step, audit_interface)?;
    result.skipped = true;
    if result.stderr.trim().is_empty() {
        result.stderr =
            "Limited mode: nmap is unavailable; this approved step recorded a skipped result."
                .to_string();
    }
    Ok(result)
}

fn copy_engine_directory(source: &Path, destination: &Path) -> Result<(), String> {
    if !is_regular_directory(source) {
        return Err(format!(
            "Bundled engine directory does not exist: {}",
            source.display()
        ));
    }
    if destination.exists() && !is_regular_directory(destination) {
        return Err(format!(
            "Engine destination is not a safe directory: {}",
            destination.display()
        ));
    }
    fs::create_dir_all(destination)
        .map_err(|error| format!("Unable to create engine directory: {error}"))?;
    for entry in fs::read_dir(source)
        .map_err(|error| format!("Unable to read bundled engine directory: {error}"))?
    {
        let entry =
            entry.map_err(|error| format!("Unable to read bundled engine entry: {error}"))?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path)
            .map_err(|error| format!("Unable to inspect bundled engine entry: {error}"))?;
        if metadata.file_type().is_symlink() {
            return Err("Bundled engine contains an unsafe symbolic link.".to_string());
        }
        if metadata.file_type().is_dir() {
            copy_engine_directory(&source_path, &destination_path)?;
        } else if metadata.file_type().is_file() {
            fs::copy(&source_path, &destination_path)
                .map_err(|error| format!("Unable to install bundled engine file: {error}"))?;
            fs::set_permissions(&destination_path, metadata.permissions())
                .map_err(|error| format!("Unable to set engine file permissions: {error}"))?;
        }
    }
    Ok(())
}

#[tauri::command]
fn install_bundled_engine(app: tauri::AppHandle) -> Result<EngineStatus, String> {
    let source = bundled_engine_path(&app)?;
    let destination = engine_path()?;
    verify_engine_manifest(&source)?;
    copy_engine_directory(&source, &destination)?;
    verify_engine_manifest(&destination)?;
    check_engine()
}

#[tauri::command]
fn authorize_audit(
    project_name: String,
    execution_state: tauri::State<'_, AuditExecutionState>,
) -> Result<(), String> {
    if project_name.trim().is_empty() {
        return Err("Project name is required before authorization.".to_string());
    }
    execution_state.authorize();
    Ok(())
}

#[tauri::command]
async fn run_audit_step(
    step_id: AuditStep,
    audit_interface: String,
    execution_state: tauri::State<'_, AuditExecutionState>,
) -> Result<AuditStepResult, String> {
    execution_state.consume_authorization()?;
    let _guard = execution_state.try_start()?;
    let audit_interface = validate_audit_interface(&audit_interface)?;
    if step_id.requires_nmap() && !command_available("nmap") {
        return tauri::async_runtime::spawn_blocking(move || {
            execute_limited_step(step_id, &audit_interface)
        })
        .await
        .map_err(|error| format!("Audit step worker failed: {error}"))?;
    }
    tauri::async_runtime::spawn_blocking(move || execute_audit_step(step_id, &audit_interface))
        .await
        .map_err(|error| format!("Audit step worker failed: {error}"))?
}

#[tauri::command]
async fn run_full_audit(
    app: tauri::AppHandle,
    audit_interface: String,
    execution_state: tauri::State<'_, AuditExecutionState>,
) -> Result<FullAuditResult, String> {
    execution_state.consume_authorization()?;
    let _guard = execution_state.try_start()?;
    let audit_interface = validate_audit_interface(&audit_interface)?;
    let mut results = Vec::new();

    for step in AUDIT_STEPS {
        app.emit(
            "audit-step-status",
            AuditStepEvent {
                step_id: step.id().to_string(),
                status: "running",
                result: None,
                error: None,
            },
        )
        .map_err(|error| format!("Unable to emit audit status: {error}"))?;

        let execution = if step.requires_nmap() && !command_available("nmap") {
            let interface = audit_interface.clone();
            tauri::async_runtime::spawn_blocking(move || execute_limited_step(step, &interface))
                .await
                .map_err(|error| format!("Audit step worker failed: {error}"))?
        } else {
            let interface = audit_interface.clone();
            tauri::async_runtime::spawn_blocking(move || execute_audit_step(step, &interface))
                .await
                .map_err(|error| format!("Audit step worker failed: {error}"))?
        };
        let result = match execution {
            Ok(result) => result,
            Err(error) => {
                app.emit(
                    "audit-step-status",
                    AuditStepEvent {
                        step_id: step.id().to_string(),
                        status: "failed",
                        result: None,
                        error: Some(error.clone()),
                    },
                )
                .map_err(|emit_error| format!("Unable to emit audit status: {emit_error}"))?;
                return Err(error);
            }
        };
        let status = if result.skipped {
            "skipped"
        } else if result.success {
            "success"
        } else {
            "failed"
        };
        app.emit(
            "audit-step-status",
            AuditStepEvent {
                step_id: step.id().to_string(),
                status,
                result: Some(result.clone()),
                error: None,
            },
        )
        .map_err(|error| format!("Unable to emit audit status: {error}"))?;

        let failed_step_id = (!result.success).then(|| step.id().to_string());
        results.push(result);
        if failed_step_id.is_some() {
            return Ok(FullAuditResult {
                success: false,
                steps: results,
                failed_step_id,
            });
        }
    }

    Ok(FullAuditResult {
        success: true,
        steps: results,
        failed_step_id: None,
    })
}

fn read_required_file(path: PathBuf) -> Result<String, String> {
    if !is_regular_file(&path) {
        return Err(format!(
            "Required report file does not exist or is not a regular file: {}",
            path.display()
        ));
    }

    fs::read_to_string(&path).map_err(|error| {
        format!(
            "Unable to read required report file {}: {error}",
            path.display()
        )
    })
}

fn read_optional_report_file(
    root: &Path,
    relative_path: &str,
    missing_files: &mut Vec<String>,
) -> Result<Option<String>, String> {
    let path = root.join(relative_path);
    if !is_regular_file(&path) {
        missing_files.push(relative_path.to_string());
        return Ok(None);
    }
    read_required_file(path).map(Some)
}

fn parse_findings(csv_content: Option<&str>) -> Result<Vec<RiskFinding>, String> {
    let Some(csv_content) = csv_content else {
        return Ok(Vec::new());
    };

    let findings = csv::Reader::from_reader(csv_content.as_bytes())
        .deserialize()
        .collect::<Result<Vec<RiskFinding>, csv::Error>>()
        .map_err(|error| format!("Unable to parse network issues register CSV: {error}"))?;
    let mut seen = HashSet::new();
    Ok(findings
        .into_iter()
        .filter(|finding| {
            seen.insert(format!(
                "{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}",
                finding.severity.trim().to_lowercase(),
                finding.asset.trim().to_lowercase(),
                finding.category.trim().to_lowercase(),
                finding.finding.trim().to_lowercase(),
                finding.recommended_action.trim().to_lowercase(),
            ))
        })
        .collect())
}

fn count_nonempty_lines(content: Option<String>) -> Option<usize> {
    content.map(|value| value.lines().filter(|line| !line.trim().is_empty()).count())
}

fn count_unique_csv_column(content: Option<String>, column: &str) -> Option<usize> {
    let content = content?;
    let mut reader = csv::Reader::from_reader(content.as_bytes());
    let index = reader
        .headers()
        .ok()?
        .iter()
        .position(|header| header == column)?;
    let values = reader
        .records()
        .filter_map(Result::ok)
        .filter_map(|record| record.get(index).map(str::to_string))
        .filter(|value| !value.is_empty())
        .collect::<std::collections::HashSet<_>>();
    Some(values.len())
}

fn gateway_posture_status(content: Option<String>) -> Option<String> {
    content.map(|value| {
        if value.lines().any(|line| line.contains(" open ")) {
            "Services observed".to_string()
        } else {
            "No open services observed".to_string()
        }
    })
}

#[tauri::command]
fn read_latest_report() -> Result<LatestReport, String> {
    let latest_lab = latest_lab_path()?;
    if !latest_lab.exists() {
        return Err(format!(
            "Latest lab directory does not exist: {}",
            latest_lab.display()
        ));
    }
    let mut missing_files = Vec::new();
    let executive_summary = read_optional_report_file(
        &latest_lab,
        "06-report/executive-summary.md",
        &mut missing_files,
    )?;
    let technical_report = read_optional_report_file(
        &latest_lab,
        "06-report/technical-report.md",
        &mut missing_files,
    )?;
    let risk_register = read_optional_report_file(
        &latest_lab,
        "04-risk/network-issues-register.csv",
        &mut missing_files,
    )?;
    let remediation_roadmap = read_optional_report_file(
        &latest_lab,
        "05-remediation/remediation-roadmap.md",
        &mut missing_files,
    )?;
    let evidence_index =
        read_optional_report_file(&latest_lab, "06-report/evidence-index.md", &mut Vec::new())?;
    let asset_inventory =
        read_optional_report_file(&latest_lab, "02-assets/asset-inventory.csv", &mut Vec::new())?;
    let asset_inventory_summary =
        read_optional_report_file(&latest_lab, "06-report/asset-inventory-summary.md", &mut Vec::new())?;
    let service_exposure_matrix =
        read_optional_report_file(&latest_lab, "03-services/service-exposure-matrix.csv", &mut Vec::new())?;
    let service_exposure_summary =
        read_optional_report_file(&latest_lab, "06-report/service-exposure-summary.md", &mut Vec::new())?;
    let local_network_config =
        read_optional_report_file(&latest_lab, "01-baseline/local-network-config.json", &mut Vec::new())?;
    let mdns_services =
        read_optional_report_file(&latest_lab, "03-services/mdns-services.csv", &mut Vec::new())?;
    let web_baseline =
        read_optional_report_file(&latest_lab, "03-services/web-baseline.csv", &mut Vec::new())?;
    let tls_certificates =
        read_optional_report_file(&latest_lab, "03-services/tls-certificates.csv", &mut Vec::new())?;
    let snapshot_diff =
        read_optional_report_file(&latest_lab, "07-history/snapshot-diff.json", &mut Vec::new())?;
    let remediation_tracking =
        read_optional_report_file(&latest_lab, "05-remediation/remediation-tracking.csv", &mut Vec::new())?;
    let governance_summary =
        read_optional_report_file(&latest_lab, "06-report/governance-summary.json", &mut Vec::new())?;
    let findings = parse_findings(risk_register.as_deref())?;
    let has_risk_register = risk_register.is_some();
    let count_severity = |severity: &str| {
        has_risk_register.then(|| {
            findings
                .iter()
                .filter(|finding| finding.severity.eq_ignore_ascii_case(severity))
                .count()
        })
    };
    let high_count = count_severity("High");
    let medium_count = count_severity("Medium");
    let low_count = count_severity("Low");
    let reachable_clients = count_nonempty_lines(read_optional_report_file(
        &latest_lab,
        "02-assets/reachable-client-ips.txt",
        &mut Vec::new(),
    )?);
    let unreachable_clients = count_nonempty_lines(read_optional_report_file(
        &latest_lab,
        "02-assets/unreachable-client-ips.txt",
        &mut Vec::new(),
    )?);
    let open_service_hosts = count_unique_csv_column(
        read_optional_report_file(
            &latest_lab,
            "03-services/reachable-open-ports.csv",
            &mut Vec::new(),
        )?,
        "ip",
    );
    let gateway_posture_status = gateway_posture_status(read_optional_report_file(
        &latest_lab,
        "03-services/gateway-service-version-summary.txt",
        &mut Vec::new(),
    )?);

    let generated_at = latest_lab
        .metadata()
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs());

    Ok(LatestReport {
        generated_at,
        lab_directory: latest_lab.display().to_string(),
        executive_summary,
        technical_report,
        risk_register,
        remediation_roadmap,
        evidence_index,
        asset_inventory,
        asset_inventory_summary,
        service_exposure_matrix,
        service_exposure_summary,
        local_network_config,
        mdns_services,
        web_baseline,
        tls_certificates,
        snapshot_diff,
        remediation_tracking,
        governance_summary,
        missing_files,
        findings,
        summary: ReportSummary {
            high_count,
            medium_count,
            low_count,
            reachable_clients,
            unreachable_clients,
            open_service_hosts,
            gateway_posture_status,
        },
    })
}

#[tauri::command]
fn read_remediation_tracking() -> Result<Vec<RemediationRecord>, String> {
    let path = latest_lab_path()?.join("05-remediation/remediation-tracking.csv");
    if !is_regular_file(&path) {
        return Ok(Vec::new());
    }
    csv::Reader::from_path(&path)
        .map_err(|error| format!("Unable to open remediation tracker: {error}"))?
        .deserialize()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("Unable to parse remediation tracker: {error}"))
}

#[tauri::command]
fn save_remediation_tracking(records: Vec<RemediationRecord>) -> Result<(), String> {
    const ALLOWED_STATUSES: [&str; 4] = ["Open", "Accepted risk", "In progress", "Remediated"];
    const ALLOWED_PRIORITIES: [&str; 4] = ["High", "Medium", "Low", "Routine"];
    if records.len() > 500 {
        return Err("Remediation tracker exceeds the supported record limit.".to_string());
    }
    for record in &records {
        if record.finding_id.len() > 80
            || record.owner.len() > 200
            || record.due_date.len() > 40
            || record.notes.len() > 2000
            || record.business_justification.len() > 2000
            || !ALLOWED_STATUSES.contains(&record.status.as_str())
            || !ALLOWED_PRIORITIES.contains(&record.priority.as_str())
        {
            return Err("Remediation tracker contains an unsupported value.".to_string());
        }
    }
    let path = latest_lab_path()?.join("05-remediation/remediation-tracking.csv");
    if path.exists() && !is_regular_file(&path) {
        return Err("Remediation tracker path is not a regular file.".to_string());
    }
    let mut writer = csv::Writer::from_path(&path)
        .map_err(|error| format!("Unable to write remediation tracker: {error}"))?;
    for record in records {
        writer.serialize(record).map_err(|error| format!("Unable to serialize remediation tracker: {error}"))?;
    }
    writer.flush().map_err(|error| format!("Unable to flush remediation tracker: {error}"))
}

fn validate_remediation_pack(pack: &RemediationPack) -> Result<(), String> {
    const ALLOWED_STATUSES: [&str; 7] = [
        "open", "assigned", "in_progress", "remediated", "accepted_risk", "retest_required",
        "verified",
    ];
    const ALLOWED_SEVERITIES: [&str; 4] = ["High", "Medium", "Low", "Routine"];
    if pack.tickets.len() > 500 || pack.findings.len() > 500 || pack.acceptance_records.len() > 500 {
        return Err("Remediation pack exceeds the supported record limit.".to_string());
    }
    let valid = |value: &str, maximum: usize| value.len() <= maximum && !value.contains('\0');
    if !valid(&pack.id, 200)
        || !valid(&pack.generated_at, 80)
        || !valid(&pack.lab_directory, 1000)
        || !valid(&pack.language, 20)
        || pack.verification_plan.iter().any(|value| !valid(value, 2000))
    {
        return Err("Remediation pack contains an unsupported value.".to_string());
    }
    for ticket in &pack.tickets {
        if !valid(&ticket.id, 80)
            || !valid(&ticket.finding_fingerprint, 200)
            || !valid(&ticket.asset, 500)
            || !valid(&ticket.category, 500)
            || !valid(&ticket.localized_finding, 4000)
            || !valid(&ticket.localized_recommended_action, 4000)
            || !valid(&ticket.owner, 200)
            || !valid(&ticket.due_date, 40)
            || !valid(&ticket.business_justification, 4000)
            || !valid(&ticket.notes, 4000)
            || !ALLOWED_STATUSES.contains(&ticket.status.as_str())
            || !ALLOWED_SEVERITIES.contains(&ticket.priority.as_str())
            || ticket.manual_steps.iter().any(|value| !valid(value, 2000))
            || ticket.validation_steps.iter().any(|value| !valid(value, 2000))
            || ticket.rollback_considerations.iter().any(|value| !valid(value, 2000))
            || ticket.evidence_references.iter().any(|value| !valid(value, 500))
        {
            return Err("Remediation pack contains an unsupported ticket value.".to_string());
        }
    }
    Ok(())
}

fn numbered_markdown(values: &[String]) -> String {
    values
        .iter()
        .enumerate()
        .map(|(index, value)| format!("{}. {}", index + 1, value.replace('\n', " ")))
        .collect::<Vec<_>>()
        .join("\n")
}

fn write_remediation_pack(directory: &Path, pack: &RemediationPack) -> Result<(), String> {
    validate_remediation_pack(pack)?;
    fs::create_dir_all(directory)
        .map_err(|error| format!("Unable to create remediation directory: {error}"))?;
    if !is_regular_directory(directory) {
        return Err("Remediation destination is not a regular directory.".to_string());
    }
    let fixed_files = [
        "remediation-pack.json",
        "remediation-tickets.csv",
        "remediation-playbook.md",
        "remediation-verification-plan.md",
        "remediation-acceptance-records.csv",
    ];
    for file in fixed_files {
        let path = directory.join(file);
        if path.exists() && !is_regular_file(&path) {
            return Err(format!("Remediation output path is not a regular file: {file}"));
        }
    }
    let json = serde_json::to_string_pretty(pack)
        .map_err(|error| format!("Unable to serialize remediation pack: {error}"))?;
    fs::write(directory.join("remediation-pack.json"), json)
        .map_err(|error| format!("Unable to write remediation pack: {error}"))?;

    let mut tickets = csv::Writer::from_path(directory.join("remediation-tickets.csv"))
        .map_err(|error| format!("Unable to write remediation tickets: {error}"))?;
    tickets.write_record([
        "id", "finding_fingerprint", "severity", "asset", "category", "finding",
        "recommended_action", "owner", "due_date", "priority", "status",
        "business_justification", "manual_steps", "validation_steps",
        "rollback_considerations", "evidence_references", "notes",
    ]).map_err(|error| format!("Unable to write remediation ticket header: {error}"))?;
    for ticket in &pack.tickets {
        tickets.write_record([
            &ticket.id, &ticket.finding_fingerprint, &ticket.severity, &ticket.asset, &ticket.category,
            &ticket.localized_finding, &ticket.localized_recommended_action, &ticket.owner, &ticket.due_date,
            &ticket.priority, &ticket.status, &ticket.business_justification, &ticket.manual_steps.join(" | "),
            &ticket.validation_steps.join(" | "), &ticket.rollback_considerations.join(" | "),
            &ticket.evidence_references.join(" | "), &ticket.notes,
        ]).map_err(|error| format!("Unable to serialize remediation ticket: {error}"))?;
    }
    tickets.flush().map_err(|error| format!("Unable to flush remediation tickets: {error}"))?;

    let mut playbook = format!("# Remediation Playbook\n\nGenerated: {}\n\n", pack.generated_at);
    for ticket in &pack.tickets {
        playbook.push_str(&format!(
            "## {} - {}\n\n**Asset:** {}\n\n**Recommended action:** {}\n\n### Manual steps\n{}\n\n### Validation steps\n{}\n\n### Rollback considerations\n{}\n\n",
            ticket.id, ticket.localized_finding.replace('\n', " "), ticket.asset.replace('\n', " "),
            ticket.localized_recommended_action.replace('\n', " "), numbered_markdown(&ticket.manual_steps),
            numbered_markdown(&ticket.validation_steps), numbered_markdown(&ticket.rollback_considerations)
        ));
    }
    fs::write(directory.join("remediation-playbook.md"), playbook)
        .map_err(|error| format!("Unable to write remediation playbook: {error}"))?;
    fs::write(
        directory.join("remediation-verification-plan.md"),
        format!("# Remediation Verification Plan\n\n{}\n", numbered_markdown(&pack.verification_plan)),
    ).map_err(|error| format!("Unable to write remediation verification plan: {error}"))?;

    let mut acceptance = csv::Writer::from_path(directory.join("remediation-acceptance-records.csv"))
        .map_err(|error| format!("Unable to write acceptance records: {error}"))?;
    acceptance.write_record(["ticket_id", "decision", "owner", "approved_at", "expires_at", "business_justification", "notes"])
        .map_err(|error| format!("Unable to write acceptance record header: {error}"))?;
    acceptance.flush().map_err(|error| format!("Unable to flush acceptance records: {error}"))?;
    Ok(())
}

#[tauri::command]
fn save_remediation_pack(pack: RemediationPack) -> Result<(), String> {
    let directory = latest_lab_path()?.join("05-remediation");
    write_remediation_pack(&directory, &pack)
}

#[tauri::command]
fn read_remediation_pack() -> Result<Option<RemediationPack>, String> {
    let path = latest_lab_path()?.join("05-remediation/remediation-pack.json");
    if !path.exists() {
        return Ok(None);
    }
    let content = read_required_file(path)?;
    serde_json::from_str(&content)
        .map(Some)
        .map_err(|error| format!("Unable to parse remediation pack: {error}"))
}

#[tauri::command]
fn open_latest_lab_folder() -> Result<(), String> {
    let latest_lab = latest_lab_path()?;
    if !latest_lab.is_dir() {
        return Err(format!(
            "Latest lab directory does not exist: {}",
            latest_lab.display()
        ));
    }

    open_fixed_folder(&latest_lab)
}

fn open_latest_report_file(relative_path: &str) -> Result<(), String> {
    let latest_lab = latest_lab_path()?;
    let report = latest_lab.join(relative_path);
    if !is_regular_file(&report) {
        return Err(format!(
            "Latest report file does not exist: {}",
            report.display()
        ));
    }
    open_fixed_folder(&report)
}

#[tauri::command]
fn open_html_report() -> Result<(), String> {
    open_latest_report_file("06-report/lanpilot-audit-report.html")
}

#[tauri::command]
fn open_excel_report() -> Result<(), String> {
    open_latest_report_file("06-report/lanpilot-audit-report.xlsx")
}

fn open_fixed_folder(path: &Path) -> Result<(), String> {
    Command::new("/usr/bin/open")
        .arg(path)
        .status()
        .map_err(|error| format!("Unable to open {}: {error}", path.display()))
        .and_then(|status| {
            if status.success() {
                Ok(())
            } else {
                Err(format!(
                    "Unable to open {}: open exited with status {status}",
                    path.display()
                ))
            }
        })
}

#[tauri::command]
fn open_export_folder() -> Result<(), String> {
    let export_folder = export_folder_path()?;
    fs::create_dir_all(&export_folder).map_err(|error| {
        format!(
            "Unable to create export directory {}: {error}",
            export_folder.display()
        )
    })?;
    open_fixed_folder(&export_folder)
}

#[tauri::command]
fn open_engine_folder() -> Result<(), String> {
    let engine = engine_path()?;
    if !is_regular_directory(&engine) {
        return Err(format!(
            "Installed engine directory does not exist: {}",
            engine.display()
        ));
    }
    open_fixed_folder(&engine)
}

fn add_directory_to_zip(
    zip: &mut zip::ZipWriter<fs::File>,
    root: &Path,
    directory: &Path,
) -> Result<(), String> {
    let entries = fs::read_dir(directory).map_err(|error| {
        format!(
            "Unable to read export directory {}: {error}",
            directory.display()
        )
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("Unable to read export entry: {error}"))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            format!("Unable to inspect export entry {}: {error}", path.display())
        })?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.file_type().is_dir() {
            add_directory_to_zip(zip, root, &path)?;
            continue;
        }
        if !metadata.file_type().is_file() {
            continue;
        }

        let relative = path.strip_prefix(root).map_err(|error| {
            format!(
                "Unable to create export path for {}: {error}",
                path.display()
            )
        })?;
        let zip_name = relative.to_string_lossy().replace('\\', "/");
        zip.start_file(
            zip_name,
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated),
        )
        .map_err(|error| format!("Unable to add file to ZIP: {error}"))?;
        let mut source = fs::File::open(&path)
            .map_err(|error| format!("Unable to open export file {}: {error}", path.display()))?;
        let mut buffer = Vec::new();
        source
            .read_to_end(&mut buffer)
            .map_err(|error| format!("Unable to read export file {}: {error}", path.display()))?;
        zip.write_all(&buffer)
            .map_err(|error| format!("Unable to write ZIP content: {error}"))?;
    }
    Ok(())
}

fn create_latest_lab_zip() -> Result<ExportResult, String> {
    let latest_lab = latest_lab_path()?;
    if !latest_lab.is_dir() {
        return Err(format!(
            "Latest lab directory does not exist: {}",
            latest_lab.display()
        ));
    }
    let export_folder = export_folder_path()?;
    fs::create_dir_all(&export_folder).map_err(|error| {
        format!(
            "Unable to create export directory {}: {error}",
            export_folder.display()
        )
    })?;
    let timestamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
    let zip_path = export_folder.join(format!("LANPilot-Audit-{timestamp}.zip"));
    let zip_file = fs::File::create(&zip_path)
        .map_err(|error| format!("Unable to create ZIP {}: {error}", zip_path.display()))?;
    let mut zip = zip::ZipWriter::new(zip_file);
    add_directory_to_zip(&mut zip, &latest_lab, &latest_lab)?;
    zip.finish()
        .map_err(|error| format!("Unable to finish ZIP {}: {error}", zip_path.display()))?;

    Ok(ExportResult {
        zip_path: zip_path.display().to_string(),
    })
}

fn command_path(command_name: &str) -> Option<PathBuf> {
    AUDIT_PATH.split(':').map(Path::new).find_map(|directory| {
        let path = directory.join(command_name);
        fs::metadata(&path)
            .ok()
            .filter(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
            .map(|_| path)
    })
}

fn capture_fixed(label: &str, command: &str, args: &[&str]) -> CommandCapture {
    match Command::new(command)
        .args(args)
        .env_clear()
        .env("PATH", AUDIT_PATH)
        .output()
    {
        Ok(output) => CommandCapture {
            label: label.to_string(),
            command: command.to_string(),
            args: args.iter().map(|value| (*value).to_string()).collect(),
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        },
        Err(error) => CommandCapture {
            label: label.to_string(),
            command: command.to_string(),
            args: args.iter().map(|value| (*value).to_string()).collect(),
            success: false,
            stdout: String::new(),
            stderr: format!("Unable to run fixed observation: {error}"),
        },
    }
}

fn parse_route_field(output: &str, field: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let trimmed = line.trim();
        trimmed
            .strip_prefix(field)
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    })
}

fn is_observable_interface(name: &str) -> bool {
    !name.starts_with("lo")
        && !name.starts_with("utun")
        && !name.starts_with("awdl")
        && !name.starts_with("llw")
        && !name.starts_with("bridge")
        && name.chars().all(|character| character.is_ascii_alphanumeric())
}

fn choose_reliability_interface(ifconfig_list: &str, default_route_interface: Option<&str>) -> String {
    if let Some(interface) = default_route_interface.filter(|value| is_observable_interface(value)) {
        return interface.to_string();
    }
    ifconfig_list
        .split_whitespace()
        .find(|name| is_observable_interface(name))
        .unwrap_or("en0")
        .to_string()
}

fn parse_ifconfig_inet(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        (fields.first() == Some(&"inet") && fields.len() > 1).then(|| fields[1].to_string())
    })
}

fn parse_ifconfig_ipv6(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        (fields.first() == Some(&"inet6") && fields.len() > 1 && !fields[1].starts_with("fe80"))
            .then(|| fields[1].to_string())
    })
}

fn parse_dhcp_value(output: &str, key: &str) -> Option<String> {
    output.lines().find_map(|line| {
        line.trim()
            .strip_prefix(key)
            .and_then(|value| value.trim().strip_prefix('='))
            .map(str::trim)
            .map(|value| value.trim_matches('{').trim_matches('}').trim().to_string())
            .filter(|value| !value.is_empty())
    })
}

fn parse_dhcp_dns(output: &str) -> Vec<String> {
    parse_dhcp_value(output, "domain_name_server")
        .map(|value| {
            value
                .split(',')
                .map(|item| item.trim().to_string())
                .filter(|item| !item.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn parse_scutil_dns_servers(output: &str) -> Vec<String> {
    let mut values = Vec::new();
    for line in output.lines() {
        if let Some(value) = line.trim().strip_prefix("nameserver") {
            if let Some((_, address)) = value.split_once(':') {
                let candidate = address.trim().to_string();
                if !candidate.is_empty() && !values.contains(&candidate) {
                    values.push(candidate);
                }
            }
        }
    }
    values
}

fn parse_scutil_scoped_resolvers(output: &str) -> Vec<String> {
    output
        .lines()
        .filter(|line| line.contains("Scoped") || line.contains("if_index"))
        .map(|line| line.trim().to_string())
        .take(8)
        .collect()
}

fn parse_ping_loss(output: &str) -> Option<f64> {
    output.lines().find_map(|line| {
        line.find("% packet loss").and_then(|position| {
            line[..position]
                .split_whitespace()
                .last()
                .and_then(|value| value.parse::<f64>().ok())
        })
    })
}

fn parse_ping_avg_jitter(output: &str) -> (Option<f64>, Option<f64>) {
    for line in output.lines() {
        if let Some((_, values)) = line.split_once('=') {
            if line.contains("round-trip") || line.contains("rtt") {
                let parts = values
                    .trim()
                    .trim_end_matches(" ms")
                    .split('/')
                    .filter_map(|value| value.parse::<f64>().ok())
                    .collect::<Vec<_>>();
                return (parts.get(1).copied(), parts.get(3).copied());
            }
        }
    }
    (None, None)
}

fn parse_listening_services(output: &str) -> Vec<serde_json::Value> {
    output
        .lines()
        .filter(|line| line.contains("LISTEN"))
        .filter_map(|line| {
            let parts = line.split_whitespace().collect::<Vec<_>>();
            let process = parts.first()?.to_string();
            let endpoint = parts.iter().rev().find(|value| value.contains(':'))?;
            let endpoint = endpoint.trim_end_matches(")");
            let (address, port) = endpoint.rsplit_once(':')?;
            let port = port.parse::<u16>().ok()?;
            Some(serde_json::json!({
                "name": process,
                "bindAddress": address.trim_start_matches("TCP").trim().trim_matches('[').trim_matches(']').to_string(),
                "port": port,
                "process": parts.first().copied().unwrap_or("unknown")
            }))
        })
        .take(80)
        .collect()
}

fn parse_curl_timing(url: &str, output: &CommandCapture) -> serde_json::Value {
    let mut dns_ms = None;
    let mut tcp_ms = None;
    let mut tls_ms = None;
    let mut ttfb_ms = None;
    let mut total_ms = None;
    let mut status = None;
    let mut remote_ip = None;
    for line in output.stdout.lines() {
        if let Some((key, value)) = line.split_once('=') {
            match key {
                "dns" => dns_ms = seconds_to_ms(value),
                "tcp" => tcp_ms = seconds_to_ms(value),
                "tls" => tls_ms = seconds_to_ms(value),
                "ttfb" => ttfb_ms = seconds_to_ms(value),
                "total" => total_ms = seconds_to_ms(value),
                "status" => status = value.parse::<u16>().ok(),
                "remote" => remote_ip = (!value.trim().is_empty()).then(|| value.trim().to_string()),
                _ => {}
            }
        }
    }
    serde_json::json!({
        "group": target_group(url),
        "url": url,
        "dnsMs": dns_ms,
        "tcpConnectMs": tcp_ms,
        "tlsMs": tls_ms,
        "ttfbMs": ttfb_ms,
        "totalMs": total_ms,
        "status": status,
        "remoteIp": remote_ip,
        "failed": !output.success
    })
}

fn seconds_to_ms(value: &str) -> Option<u64> {
    value
        .trim()
        .parse::<f64>()
        .ok()
        .map(|seconds| (seconds * 1000.0).round() as u64)
}

fn target_group(url: &str) -> &'static str {
    if url.contains("apple.com.cn") {
        "china_mainland"
    } else if url.contains("github") {
        "developer"
    } else if url.contains("cloudflare") {
        "cdn"
    } else {
        "apple"
    }
}

fn json_number(value: Option<f64>) -> serde_json::Value {
    value
        .and_then(serde_json::Number::from_f64)
        .map(serde_json::Value::Number)
        .unwrap_or(serde_json::Value::Null)
}

fn json_u64(value: Option<u64>) -> serde_json::Value {
    value
        .map(|item| serde_json::Value::Number(serde_json::Number::from(item)))
        .unwrap_or(serde_json::Value::Null)
}

fn bool_from_json(value: &serde_json::Value, path: &[&str]) -> bool {
    path.iter()
        .try_fold(value, |current, key| current.get(*key))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

fn string_from_json(value: &serde_json::Value, path: &[&str]) -> Option<String> {
    path.iter()
        .try_fold(value, |current, key| current.get(*key))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

fn number_from_json(value: &serde_json::Value, path: &[&str]) -> Option<f64> {
    path.iter()
        .try_fold(value, |current, key| current.get(*key))
        .and_then(serde_json::Value::as_f64)
}

fn array_len(value: &serde_json::Value, path: &[&str]) -> usize {
    path.iter()
        .try_fold(value, |current, key| current.get(*key))
        .and_then(serde_json::Value::as_array)
        .map(Vec::len)
        .unwrap_or(0)
}

fn external_targets(value: &serde_json::Value) -> Vec<&serde_json::Value> {
    value
        .get("external")
        .and_then(|external| external.get("targets"))
        .and_then(serde_json::Value::as_array)
        .map(|targets| targets.iter().collect())
        .unwrap_or_default()
}

fn physical_status_from_evidence(evidence: &serde_json::Value) -> &'static str {
    let dhcp_ok = bool_from_json(evidence, &["physicalLan", "dhcpOk"]);
    let self_assigned = bool_from_json(evidence, &["physicalLan", "selfAssignedAddress"]);
    let has_ipv4 = string_from_json(evidence, &["physicalLan", "ipv4"]).is_some();
    let has_gateway = string_from_json(evidence, &["physicalLan", "gatewayIp"]).is_some();
    if !dhcp_ok || self_assigned || !has_ipv4 || !has_gateway {
        return "critical";
    }
    let loss = number_from_json(evidence, &["physicalLan", "gatewayPingLossPct"]).unwrap_or(0.0);
    let latency = number_from_json(evidence, &["physicalLan", "gatewayPingAvgMs"]).unwrap_or(0.0);
    if loss >= 5.0 || latency > 50.0 {
        "critical"
    } else if loss > 0.0 || latency > 30.0 {
        "warning"
    } else {
        "healthy"
    }
}

fn dns_status_from_evidence(evidence: &serde_json::Value) -> &'static str {
    if bool_from_json(evidence, &["physicalLan", "gatewayDnsTimedOut"]) {
        return "critical";
    }
    let gateway_dns = number_from_json(evidence, &["physicalLan", "gatewayDnsMs"]).unwrap_or(0.0);
    if gateway_dns > 100.0
        || bool_from_json(evidence, &["overlay", "dnsViaOverlay"])
        || bool_from_json(evidence, &["overlay", "hasTailscaleDns100100"])
        || bool_from_json(evidence, &["overlay", "hasTailscaleIpv6Dns"])
    {
        "warning"
    } else if array_len(evidence, &["localControlPlane", "systemDnsServers"]) > 0 {
        "healthy"
    } else {
        "unknown"
    }
}

fn overlay_status_from_evidence(evidence: &serde_json::Value) -> &'static str {
    let default_route = string_from_json(evidence, &["overlay", "defaultRouteInterface"]).unwrap_or_default();
    if bool_from_json(evidence, &["overlay", "multipleOverlayComponents"])
        || bool_from_json(evidence, &["overlay", "tailscaleExitNode"])
        || bool_from_json(evidence, &["overlay", "stashTunDetected"])
        || default_route.starts_with("utun")
    {
        "warning"
    } else {
        "healthy"
    }
}

fn external_status_from_evidence(evidence: &serde_json::Value) -> &'static str {
    let targets = external_targets(evidence);
    if targets.is_empty() {
        return "unknown";
    }
    let failures = targets
        .iter()
        .filter(|target| target.get("failed").and_then(serde_json::Value::as_bool).unwrap_or(false))
        .count();
    if failures == targets.len() {
        return "critical";
    }
    let slow = targets.iter().any(|target| {
        target.get("failed").and_then(serde_json::Value::as_bool).unwrap_or(false)
            || target.get("totalMs").and_then(serde_json::Value::as_f64).unwrap_or(0.0) > 3000.0
            || target.get("tcpConnectMs").and_then(serde_json::Value::as_f64).unwrap_or(0.0) > 1000.0
            || target.get("tlsMs").and_then(serde_json::Value::as_f64).unwrap_or(0.0) > 1500.0
            || target.get("ttfbMs").and_then(serde_json::Value::as_f64).unwrap_or(0.0) > 2000.0
    });
    if slow {
        "warning"
    } else {
        "healthy"
    }
}

fn exposed_local_service(evidence: &serde_json::Value) -> Option<String> {
    const PORTS: [u64; 9] = [3000, 5000, 5173, 6379, 7474, 7687, 5432, 3306, 8080];
    evidence
        .get("localControlPlane")
        .and_then(|value| value.get("listeningServices"))
        .and_then(serde_json::Value::as_array)
        .and_then(|services| {
            services.iter().find_map(|service| {
                let port = service.get("port").and_then(serde_json::Value::as_u64)?;
                let bind = service.get("bindAddress").and_then(serde_json::Value::as_str)?;
                (PORTS.contains(&port) && matches!(bind, "0.0.0.0" | "*" | "::")).then(|| {
                    format!(
                        "{} listens on {bind}:{port}",
                        service.get("name").and_then(serde_json::Value::as_str).unwrap_or("Service")
                    )
                })
            })
        })
}

fn network_path_from_evidence(evidence: &serde_json::Value) -> String {
    let interface = string_from_json(evidence, &["physicalLan", "activeInterface"]).unwrap_or_else(|| "interface".to_string());
    let gateway = string_from_json(evidence, &["physicalLan", "gatewayIp"]).unwrap_or_else(|| "gateway".to_string());
    let default_route = string_from_json(evidence, &["overlay", "defaultRouteInterface"]).unwrap_or_default();
    if bool_from_json(evidence, &["overlay", "tailscaleRunning"])
        && bool_from_json(evidence, &["overlay", "tailscaleExitNode"])
    {
        "Mac -> Tailscale / utun -> Exit Node -> Internet".to_string()
    } else if bool_from_json(evidence, &["overlay", "stashDetected"])
        && bool_from_json(evidence, &["overlay", "stashTunDetected"])
    {
        "Mac -> Stash TUN / utun -> Proxy rules -> Proxy exit -> Internet".to_string()
    } else if default_route.starts_with("utun") {
        "Mac -> Overlay / utun -> Remote path -> Internet".to_string()
    } else {
        format!("Mac -> {interface} -> {gateway} -> ISP -> Internet")
    }
}

fn build_reliability_summary(evidence: &serde_json::Value) -> serde_json::Value {
    let physical_status = physical_status_from_evidence(evidence);
    let dns_status = dns_status_from_evidence(evidence);
    let overlay_status = overlay_status_from_evidence(evidence);
    let external_status = external_status_from_evidence(evidence);
    let gateway_loss = number_from_json(evidence, &["physicalLan", "gatewayPingLossPct"]).unwrap_or(0.0);
    let gateway_latency = number_from_json(evidence, &["physicalLan", "gatewayPingAvgMs"]).unwrap_or(0.0);
    let gateway_dns = number_from_json(evidence, &["physicalLan", "gatewayDnsMs"]).unwrap_or(0.0);
    let default_route = string_from_json(evidence, &["overlay", "defaultRouteInterface"]).unwrap_or_default();
    let all_external_failed = external_status == "critical";
    let external_slow = external_status == "warning" || all_external_failed;
    let physical_healthy = physical_status == "healthy";
    let default_route_overlay = default_route.starts_with("utun");
    let tailscale_dns = bool_from_json(evidence, &["overlay", "hasTailscaleDns100100"])
        || bool_from_json(evidence, &["overlay", "hasTailscaleIpv6Dns"]);

    let mut fault_domain = "none";
    let mut fault_point = "No clear fault point detected.".to_string();
    let mut impact = "No immediate user-visible impact is indicated by the supplied observations.".to_string();
    let mut key_evidence = Vec::new();
    let mut advice = Vec::new();
    let mut retest = Vec::new();

    if physical_status == "critical"
        && (!bool_from_json(evidence, &["physicalLan", "dhcpOk"])
            || bool_from_json(evidence, &["physicalLan", "selfAssignedAddress"]))
    {
        fault_domain = "dhcp";
        fault_point = "DHCP or local link issue detected.".to_string();
        impact = "The Mac may not have a usable local network path.".to_string();
        key_evidence.push("The active interface does not have a complete DHCP address, router, and DNS set.".to_string());
        key_evidence.push(format!(
            "Interface {} has IPv4 {}.",
            string_from_json(evidence, &["physicalLan", "activeInterface"]).unwrap_or_else(|| "unknown".to_string()),
            string_from_json(evidence, &["physicalLan", "ipv4"]).unwrap_or_else(|| "none".to_string())
        ));
        advice.push("Check router DHCP service and the local link before testing external sites.".to_string());
        advice.push("Check cable, Wi-Fi association, adapter, or switch port outside LANPilot.".to_string());
        retest.push("Renew the lease outside LANPilot, then run Network Reliability again.".to_string());
    } else if physical_status == "critical" || gateway_loss > 0.0 || gateway_latency > 50.0 {
        fault_domain = "gateway";
        fault_point = "Local gateway or physical link instability detected.".to_string();
        impact = "Local network instability can affect DNS, browsing, and app connectivity before traffic reaches the internet.".to_string();
        key_evidence.push(format!("Gateway packet loss is {gateway_loss}%."));
        key_evidence.push(format!("Gateway average latency is {gateway_latency} ms."));
        advice.push("Check Ethernet cable, switch port, router load, and USB Ethernet adapter.".to_string());
        advice.push("Retest with the current physical path isolated from overlay and proxy changes.".to_string());
        retest.push("Run gateway ping and gateway DNS timing again after the physical path is checked.".to_string());
    } else if physical_healthy && gateway_dns > 100.0 {
        fault_domain = "local_dns";
        fault_point = "Local DNS resolver or router DNS forwarding issue detected.".to_string();
        impact = "Name resolution can be slow even when the local gateway is reachable.".to_string();
        key_evidence.push(format!("Gateway DNS timing is {gateway_dns} ms."));
        key_evidence.push(format!("Gateway ping loss is {gateway_loss}% with average latency {gateway_latency} ms."));
        advice.push("Check router DNS forwarding and upstream DNS settings.".to_string());
        advice.push("Compare system DNS with direct gateway DNS, then review overlay DNS policy if present.".to_string());
        retest.push("Retest gateway DNS and system DNS separately.".to_string());
    } else if bool_from_json(evidence, &["overlay", "tailscaleRunning"])
        && bool_from_json(evidence, &["overlay", "tailscaleExitNode"])
        && default_route_overlay
        && tailscale_dns
        && external_slow
    {
        fault_domain = "tailscale_exit_node";
        fault_point = "Tailscale Exit Node may be affecting external connectivity.".to_string();
        impact = "External traffic may be routed through a remote exit path instead of the local ISP path.".to_string();
        key_evidence.push("Default route uses an overlay interface while Tailscale is running as an exit path.".to_string());
        key_evidence.push("DNS uses Tailscale DNS and HTTPS timing is slow or failed.".to_string());
        advice.push("Disable Exit Node outside LANPilot and retest.".to_string());
        advice.push("Disable Tailscale DNS if it is not needed for this workflow.".to_string());
        retest.push("Compare external HTTPS timing before and after the Exit Node change.".to_string());
    } else if bool_from_json(evidence, &["overlay", "multipleOverlayComponents"])
        && default_route_overlay
        && bool_from_json(evidence, &["overlay", "dnsViaOverlay"])
    {
        fault_domain = "overlay_proxy";
        fault_point = "Multiple overlay or proxy components are present and may conflict.".to_string();
        impact = "Routing and DNS may be controlled by different local components, causing inconsistent connectivity.".to_string();
        key_evidence.push(format!("Default route interface is {default_route}."));
        key_evidence.push("Multiple overlay components and overlay DNS were detected.".to_string());
        advice.push("Choose one component to control general internet access.".to_string());
        advice.push("Avoid enabling multiple overlay route controllers at the same time.".to_string());
        retest.push("Retest default route and DNS after changing overlay state outside LANPilot.".to_string());
    } else if let Some(local_service) = exposed_local_service(evidence) {
        fault_domain = "local_service_exposure";
        fault_point = "Local development service may be reachable from the LAN.".to_string();
        impact = "A local service that should be private may be visible to nearby network clients.".to_string();
        key_evidence.push(local_service);
        key_evidence.push("The service is not limited to the loopback address.".to_string());
        advice.push("Bind development services to 127.0.0.1 if LAN access is not required.".to_string());
        advice.push("Avoid exposing local databases to the LAN unless it is intentional and documented.".to_string());
        retest.push("Retest local listening services after changing the service bind address outside LANPilot.".to_string());
    } else if physical_healthy
        && bool_from_json(evidence, &["overlay", "stashDetected"])
        && bool_from_json(evidence, &["overlay", "stashTunDetected"])
        && default_route_overlay
    {
        fault_domain = if external_slow { "overlay_proxy" } else { "none" };
        fault_point = if external_slow {
            "Proxy overlay path is the likely place to inspect.".to_string()
        } else {
            "Physical LAN is healthy; internet path is currently handled by Stash TUN.".to_string()
        };
        impact = if external_slow {
            "External access may depend on proxy node, rule, DNS policy, or proxy exit quality.".to_string()
        } else {
            "No physical LAN fault is indicated; traffic is intentionally using an overlay path.".to_string()
        };
        key_evidence.push("Physical LAN has DHCP, router, and stable gateway reachability.".to_string());
        key_evidence.push("Default route uses an overlay interface and Stash indicators are present.".to_string());
        advice.push("If external access is slow, check Stash node, rule routing, DNS policy, and proxy exit.".to_string());
        advice.push("Compare direct gateway DNS with system DNS before blaming the router.".to_string());
        retest.push("Retest once with the overlay disabled outside LANPilot, then retest with Stash enabled.".to_string());
    } else if physical_healthy && all_external_failed && default_route_overlay {
        fault_domain = "overlay_proxy";
        fault_point = "External connectivity failure is likely in the overlay or proxy path.".to_string();
        impact = "Local LAN appears usable, but internet access through the overlay path fails.".to_string();
        key_evidence.push("Gateway reachability and DNS are healthy.".to_string());
        key_evidence.push("All external HTTPS targets failed while default route uses an overlay interface.".to_string());
        advice.push("Check proxy account, node health, firewall policy, and DNS policy.".to_string());
        advice.push("Retest direct gateway path outside LANPilot.".to_string());
        retest.push("Run Network Reliability again after changing the overlay state outside LANPilot.".to_string());
    } else if physical_healthy && external_slow {
        fault_domain = if default_route_overlay { "proxy_exit" } else { "external_path" };
        fault_point = if default_route_overlay {
            "Proxy exit or external path performance issue detected.".to_string()
        } else {
            "External path or remote service performance issue detected.".to_string()
        };
        impact = "Local LAN checks are healthy, so user-visible slowness is likely beyond the local gateway.".to_string();
        key_evidence.push("Gateway ping and local DNS are healthy.".to_string());
        key_evidence.push("DNS, TCP, TLS, TTFB, or total HTTPS timing is slow for one or more external targets.".to_string());
        advice.push("Check proxy node, ISP route, target service status, and CDN region.".to_string());
        advice.push("Retest with proxy disabled and enabled outside LANPilot.".to_string());
        retest.push("Compare HTTPS timing across Apple, developer, CDN, and mainland reference targets.".to_string());
    }

    if key_evidence.is_empty() {
        key_evidence.push("DHCP address, gateway, DNS, and external timing do not show a critical condition.".to_string());
        key_evidence.push(format!("Current path: {}.", network_path_from_evidence(evidence)));
        advice.push("Save this result as a baseline for future comparison.".to_string());
        advice.push("If the user experience changes, compare a new snapshot against this baseline.".to_string());
        retest.push("Run the same check after any proxy, VPN, Wi-Fi, or adapter change.".to_string());
    }

    let overall_status = if [physical_status, dns_status, overlay_status, external_status].contains(&"critical") {
        "critical"
    } else if fault_domain != "none"
        || [physical_status, dns_status, overlay_status, external_status].contains(&"warning")
    {
        "warning"
    } else {
        "healthy"
    };

    serde_json::json!({
        "overallStatus": overall_status,
        "physicalLanStatus": physical_status,
        "dnsStatus": dns_status,
        "overlayStatus": overlay_status,
        "externalPathStatus": external_status,
        "faultDomain": fault_domain,
        "faultPoint": fault_point,
        "currentPath": network_path_from_evidence(evidence),
        "impact": impact,
        "evidence": key_evidence,
        "remediationAdvice": advice,
        "retestPlan": retest,
        "rawEvidenceRefs": ["network-environment-evidence.json"]
    })
}

fn markdown_list(values: Option<&Vec<serde_json::Value>>) -> String {
    values
        .map(|items| {
            items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(|item| format!("- {item}"))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "- None".to_string())
}

fn build_network_reliability_report(summary: &serde_json::Value, evidence: &serde_json::Value) -> String {
    let summary_items = |key: &str| summary.get(key).and_then(serde_json::Value::as_array);
    let target_lines = external_targets(evidence)
        .iter()
        .map(|target| {
            format!(
                "- {}: total={} ms, status={}",
                target.get("url").and_then(serde_json::Value::as_str).unwrap_or("unknown"),
                target.get("totalMs").and_then(serde_json::Value::as_u64).map(|value| value.to_string()).unwrap_or_else(|| "unknown".to_string()),
                target.get("status").and_then(serde_json::Value::as_u64).map(|value| value.to_string()).unwrap_or_else(|| "unknown".to_string())
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let services = evidence
        .get("localControlPlane")
        .and_then(|value| value.get("listeningServices"))
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|service| {
                    format!(
                        "- {} {}:{}",
                        service.get("name").and_then(serde_json::Value::as_str).unwrap_or("Service"),
                        service.get("bindAddress").and_then(serde_json::Value::as_str).unwrap_or("unknown"),
                        service.get("port").and_then(serde_json::Value::as_u64).map(|value| value.to_string()).unwrap_or_else(|| "unknown".to_string())
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        })
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "- None".to_string());

    format!(
        "# Network Reliability Report\n\n## Overall Diagnosis\n\n{}\n\n## Current Network Path\n\n{}\n\n## Fault Point\n\n{}\n\n## Impact\n\n{}\n\n## Key Evidence\n\n{}\n\n## Troubleshooting Advice\n\n{}\n\n## Retest Plan\n\n{}\n\n## Physical LAN\n\n- Interface: {}\n- Gateway: {}\n- Gateway latency: {} ms\n\n## DNS\n\n- System DNS: {}\n- Gateway DNS: {} ms\n\n## Overlay / Proxy / VPN\n\n- Default route interface: {}\n- Overlay interfaces: {}\n\n## External Internet\n\n{}\n\n## Local Listening Services\n\n{}\n\n## Raw Evidence\n\n- network-environment-evidence.json\n",
        summary.get("overallStatus").and_then(serde_json::Value::as_str).unwrap_or("unknown"),
        summary.get("currentPath").and_then(serde_json::Value::as_str).unwrap_or("unknown"),
        summary.get("faultPoint").and_then(serde_json::Value::as_str).unwrap_or("unknown"),
        summary.get("impact").and_then(serde_json::Value::as_str).unwrap_or("unknown"),
        markdown_list(summary_items("evidence")),
        markdown_list(summary_items("remediationAdvice")),
        markdown_list(summary_items("retestPlan")),
        string_from_json(evidence, &["physicalLan", "activeInterface"]).unwrap_or_else(|| "unknown".to_string()),
        string_from_json(evidence, &["physicalLan", "gatewayIp"]).unwrap_or_else(|| "unknown".to_string()),
        number_from_json(evidence, &["physicalLan", "gatewayPingAvgMs"]).map(|value| value.to_string()).unwrap_or_else(|| "unknown".to_string()),
        evidence.get("localControlPlane").and_then(|value| value.get("systemDnsServers")).and_then(serde_json::Value::as_array).map(|items| items.iter().filter_map(serde_json::Value::as_str).collect::<Vec<_>>().join(", ")).filter(|value| !value.is_empty()).unwrap_or_else(|| "unknown".to_string()),
        number_from_json(evidence, &["physicalLan", "gatewayDnsMs"]).map(|value| value.to_string()).unwrap_or_else(|| "unknown".to_string()),
        string_from_json(evidence, &["overlay", "defaultRouteInterface"]).unwrap_or_else(|| "unknown".to_string()),
        evidence.get("overlay").and_then(|value| value.get("utunInterfaces")).and_then(serde_json::Value::as_array).map(|items| items.iter().filter_map(serde_json::Value::as_str).collect::<Vec<_>>().join(", ")).filter(|value| !value.is_empty()).unwrap_or_else(|| "none".to_string()),
        if target_lines.is_empty() { "- None".to_string() } else { target_lines },
        services
    )
}

fn build_network_reliability_retest(summary: &serde_json::Value) -> String {
    format!(
        "# Network Reliability Retest Plan\n\n{}\n",
        markdown_list(summary.get("retestPlan").and_then(serde_json::Value::as_array))
    )
}

fn redact_text_for_support_bundle(input: &str, home: &Path) -> String {
    let home_string = home.display().to_string();
    let mut output = input.replace(&home_string, "/Users/demo");
    for value in extract_ipv4_candidates(input) {
        output = output.replace(&value, "192.0.2.10");
    }
    for value in extract_mac_candidates(input) {
        output = output.replace(&value, "00:00:00:00:00:00");
    }
    output
}

fn extract_ipv4_candidates(input: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut current = String::new();
    for character in input.chars().chain(std::iter::once(' ')) {
        if character.is_ascii_digit() || character == '.' {
            current.push(character);
        } else {
            let parts = current.split('.').collect::<Vec<_>>();
            if parts.len() == 4 && parts.iter().all(|part| part.parse::<u8>().is_ok()) {
                values.push(current.clone());
            }
            current.clear();
        }
    }
    values.sort();
    values.dedup();
    values
}

fn extract_mac_candidates(input: &str) -> Vec<String> {
    let mut values = Vec::new();
    for token in input.split(|character: char| character.is_whitespace() || matches!(character, ',' | ';' | ')' | '(')) {
        let candidate = token.trim_matches(|character: char| matches!(character, '"' | '\''));
        let parts = candidate.split(':').collect::<Vec<_>>();
        if parts.len() == 6
            && parts.iter().all(|part| part.len() == 2 && part.chars().all(|character| character.is_ascii_hexdigit()))
        {
            values.push(candidate.to_string());
        }
    }
    values.sort();
    values.dedup();
    values
}

fn write_redacted_support_bundle(
    output_directory: &Path,
    files: &[(&str, String)],
    home: &Path,
) -> Result<PathBuf, String> {
    let bundle_path = output_directory.join("network-environment-redacted-support-bundle.zip");
    let bundle = fs::File::create(&bundle_path)
        .map_err(|error| format!("Unable to create reliability support bundle: {error}"))?;
    let mut zip = zip::ZipWriter::new(bundle);
    for (name, content) in files {
        zip.start_file(
            *name,
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated),
        )
        .map_err(|error| format!("Unable to add reliability support file: {error}"))?;
        zip.write_all(redact_text_for_support_bundle(content, home).as_bytes())
            .map_err(|error| format!("Unable to write reliability support file: {error}"))?;
    }
    zip.finish()
        .map_err(|error| format!("Unable to finish reliability support bundle: {error}"))?;
    Ok(bundle_path)
}

fn capture_curl_target(url: &str) -> CommandCapture {
    capture_fixed(
        &format!("curl-{url}"),
        "/usr/bin/curl",
        &[
            "--head",
            "--location",
            "--max-time",
            "6",
            "--silent",
            "--show-error",
            "--output",
            "/dev/null",
            "--write-out",
            "dns=%{time_namelookup}\ntcp=%{time_connect}\ntls=%{time_appconnect}\nttfb=%{time_starttransfer}\ntotal=%{time_total}\nstatus=%{http_code}\nremote=%{remote_ip}\n",
            url,
        ],
    )
}

fn collect_network_reliability() -> Result<NetworkReliabilityRun, String> {
    let home = home_path()?;
    let output_directory = latest_lab_path()?.join("08-network-reliability");
    fs::create_dir_all(&output_directory)
        .map_err(|error| format!("Unable to create reliability output directory: {error}"))?;
    if !is_regular_directory(&output_directory) {
        return Err("Reliability output destination is not a regular directory.".to_string());
    }

    let ifconfig_list = capture_fixed("ifconfig-list", "/sbin/ifconfig", &["-l"]);
    let route_default = capture_fixed("route-default", "/sbin/route", &["-n", "get", "default"]);
    let default_route_interface = parse_route_field(&route_default.stdout, "interface:");
    let default_route_gateway = parse_route_field(&route_default.stdout, "gateway:");
    let active_interface = choose_reliability_interface(&ifconfig_list.stdout, default_route_interface.as_deref());
    let interface_detail = capture_fixed("ifconfig-interface", "/sbin/ifconfig", &[&active_interface]);
    let ipconfig = capture_fixed("ipconfig-getpacket", "/usr/sbin/ipconfig", &["getpacket", &active_interface]);
    let scutil_dns = capture_fixed("scutil-dns", "/usr/sbin/scutil", &["--dns"]);
    let netstat_routes = capture_fixed("netstat-routes", "/usr/sbin/netstat", &["-rn"]);
    let arp_table = capture_fixed("arp-table", "/usr/sbin/arp", &["-an"]);
    let lsof_listen = capture_fixed("lsof-listen", "/usr/sbin/lsof", &["-nP", "-iTCP", "-sTCP:LISTEN"]);
    let sw_vers = capture_fixed("sw-vers", "/usr/bin/sw_vers", &[]);
    let gateway = default_route_gateway
        .clone()
        .or_else(|| parse_dhcp_value(&ipconfig.stdout, "router"));
    let ping_gateway = gateway
        .as_deref()
        .map(|gateway_ip| capture_fixed("gateway-ping", "/sbin/ping", &["-c", "3", "-n", "-q", gateway_ip]));
    let gateway_dns_start = Instant::now();
    let gateway_dns = if let Some(gateway_ip) = gateway.as_deref() {
        if let Some(dig) = command_path("dig") {
            let dig_command = dig.display().to_string();
            let resolver = format!("@{gateway_ip}");
            let dig_args = [
                resolver.as_str(),
                "apple.com",
                "A",
                "+time=2",
                "+tries=1",
            ];
            Some(capture_fixed("gateway-dns", &dig_command, &dig_args))
        } else {
            None
        }
    } else {
        None
    };
    let gateway_dns_ms = gateway_dns
        .as_ref()
        .filter(|capture| capture.success)
        .map(|_| gateway_dns_start.elapsed().as_millis() as u64);
    let tailscale_status = command_path("tailscale")
        .map(|path| capture_fixed("tailscale-status", &path.display().to_string(), &["status"]));
    let tailscale_netcheck = command_path("tailscale")
        .map(|path| capture_fixed("tailscale-netcheck", &path.display().to_string(), &["netcheck"]));
    let targets = [
        "https://www.apple.com",
        "https://github.com",
        "https://www.cloudflare.com",
        "https://www.apple.com.cn",
    ];
    let curl_captures = targets.map(capture_curl_target);

    let (gateway_loss, gateway_avg, gateway_jitter) = ping_gateway
        .as_ref()
        .map(|capture| {
            let (average, jitter) = parse_ping_avg_jitter(&capture.stdout);
            (parse_ping_loss(&capture.stdout), average, jitter)
        })
        .unwrap_or((None, None, None));
    let ipv4 = parse_ifconfig_inet(&interface_detail.stdout);
    let ipv6 = parse_ifconfig_ipv6(&interface_detail.stdout);
    let self_assigned = ipv4.as_deref().map(|value| value.starts_with("169.254.")).unwrap_or(false);
    let dhcp_dns = parse_dhcp_dns(&ipconfig.stdout);
    let system_dns = parse_scutil_dns_servers(&scutil_dns.stdout);
    let scoped_resolvers = parse_scutil_scoped_resolvers(&scutil_dns.stdout);
    let utun_interfaces = ifconfig_list
        .stdout
        .split_whitespace()
        .filter(|name| name.starts_with("utun"))
        .map(str::to_string)
        .collect::<Vec<_>>();
    let lsof_lower = lsof_listen.stdout.to_lowercase();
    let netstat_lower = netstat_routes.stdout.to_lowercase();
    let scutil_lower = scutil_dns.stdout.to_lowercase();
    let tailscale_text = format!(
        "{}\n{}",
        tailscale_status.as_ref().map(|capture| capture.stdout.as_str()).unwrap_or(""),
        tailscale_netcheck.as_ref().map(|capture| capture.stdout.as_str()).unwrap_or("")
    );
    let tailscale_lower = tailscale_text.to_lowercase();
    let stash_detected = lsof_lower.contains("stash") || lsof_listen.stdout.contains(":7890") || lsof_listen.stdout.contains(":9090");
    let has_tailscale_dns = system_dns.iter().any(|value| value == "100.100.100.100");
    let has_tailscale_ipv6_dns = system_dns.iter().any(|value| value.to_lowercase().starts_with("fd7a:115c:a1e0"));
    let tailscale_running = tailscale_status.as_ref().map(|capture| capture.success && !capture.stdout.trim().is_empty()).unwrap_or(false);
    let tailscale_exit_node = tailscale_lower.contains("exit node") || (tailscale_running && default_route_interface.as_deref().unwrap_or("").starts_with("utun"));
    let has_proxy_range = netstat_lower.contains("198.18") || system_dns.iter().any(|value| value.starts_with("198.18."));
    let has_tailscale_range = netstat_lower.contains("100.64") || has_tailscale_dns;
    let wireguard_detected = netstat_lower.contains("wireguard") || lsof_lower.contains("wireguard");
    let openvpn_detected = lsof_lower.contains("openvpn");
    let clash_detected = lsof_lower.contains("clash");
    let surge_detected = lsof_lower.contains("surge");
    let overlay_count = [
        stash_detected,
        tailscale_running,
        wireguard_detected,
        openvpn_detected,
        clash_detected,
        surge_detected,
    ]
    .into_iter()
    .filter(|value| *value)
    .count();
    let dns_via_overlay = has_proxy_range || has_tailscale_dns || has_tailscale_ipv6_dns || scutil_lower.contains("utun");
    let profile = if tailscale_exit_node {
        "Tailscale Remote Access"
    } else if overlay_count > 0 || default_route_interface.as_deref().unwrap_or("").starts_with("utun") {
        "VPN / Proxy Active"
    } else if ipv4.as_deref().map(|value| value.starts_with("172.20.10.")).unwrap_or(false) {
        "Mobile Hotspot"
    } else {
        "Home LAN"
    };
    let listening_services = parse_listening_services(&lsof_listen.stdout);
    let external_targets = curl_captures
        .iter()
        .map(|capture| parse_curl_timing(capture.args.last().map(String::as_str).unwrap_or("unknown"), capture))
        .collect::<Vec<_>>();
    let stash_ports = [7890, 9090]
        .into_iter()
        .filter(|port| lsof_listen.stdout.contains(&format!(":{port}")))
        .collect::<Vec<_>>();
    let captures = {
        let mut values = vec![
            ifconfig_list.clone(),
            route_default.clone(),
            interface_detail.clone(),
            ipconfig.clone(),
            scutil_dns.clone(),
            netstat_routes.clone(),
            arp_table.clone(),
            lsof_listen.clone(),
            sw_vers.clone(),
        ];
        if let Some(capture) = ping_gateway.clone() {
            values.push(capture);
        }
        if let Some(capture) = gateway_dns.clone() {
            values.push(capture);
        }
        if let Some(capture) = tailscale_status.clone() {
            values.push(capture);
        }
        if let Some(capture) = tailscale_netcheck.clone() {
            values.push(capture);
        }
        values.extend(curl_captures.iter().cloned());
        values
    };
    let raw_captures = captures
        .iter()
        .map(|capture| serde_json::json!({
            "label": capture.label,
            "command": capture.command,
            "args": capture.args,
            "success": capture.success,
            "stdout": capture.stdout,
            "stderr": capture.stderr
        }))
        .collect::<Vec<_>>();
    let evidence = serde_json::json!({
        "profile": profile,
        "generatedAt": chrono::Local::now().to_rfc3339(),
        "physicalLan": {
            "activeInterface": active_interface.clone(),
            "interfaceKind": if active_interface == "en0" { "wifi" } else { "wired" },
            "ipv4": ipv4,
            "ipv6": ipv6,
            "subnetMask": serde_json::Value::Null,
            "dhcpOk": !self_assigned && gateway.is_some(),
            "dhcpServer": parse_dhcp_value(&ipconfig.stdout, "server_identifier"),
            "dhcpRouter": parse_dhcp_value(&ipconfig.stdout, "router"),
            "dhcpDns": dhcp_dns,
            "dhcpLeaseSeconds": parse_dhcp_value(&ipconfig.stdout, "lease_time").and_then(|value| value.parse::<u64>().ok()),
            "gatewayIp": gateway,
            "gatewayPingLossPct": json_number(gateway_loss),
            "gatewayPingAvgMs": json_number(gateway_avg),
            "gatewayPingJitterMs": json_number(gateway_jitter),
            "gatewayDnsMs": json_u64(gateway_dns_ms),
            "gatewayDnsTimedOut": gateway_dns.as_ref().map(|capture| !capture.success).unwrap_or(false),
            "arpSummary": format!("{} ARP neighbor rows observed", arp_table.stdout.lines().filter(|line| !line.trim().is_empty()).count()),
            "selfAssignedAddress": self_assigned,
            "multipleActiveInterfaces": false
        },
        "localControlPlane": {
            "systemDnsServers": system_dns,
            "scopedResolvers": scoped_resolvers,
            "resolverSummary": "System resolver snapshot collected locally",
            "mdnsSummary": "mDNS is observed by the main audit workflow when that workflow is run",
            "listeningServices": listening_services
        },
        "overlay": {
            "defaultRouteInterface": default_route_interface.clone(),
            "defaultRouteGateway": default_route_gateway,
            "utunInterfaces": utun_interfaces,
            "hasProxyRange19818": has_proxy_range,
            "hasTailscaleRange10064": has_tailscale_range,
            "hasTailscaleDns100100": has_tailscale_dns,
            "hasTailscaleIpv6Dns": has_tailscale_ipv6_dns,
            "tailscaleRunning": tailscale_running,
            "tailscaleExitNode": tailscale_exit_node,
            "tailscaleDnsEnabled": has_tailscale_dns || has_tailscale_ipv6_dns,
            "stashDetected": stash_detected,
            "stashTunDetected": stash_detected && default_route_interface.as_deref().unwrap_or("").starts_with("utun"),
            "stashPorts": stash_ports,
            "clashDetected": clash_detected,
            "surgeDetected": surge_detected,
            "wireGuardDetected": wireguard_detected,
            "openVpnDetected": openvpn_detected,
            "multipleOverlayComponents": overlay_count > 1,
            "dnsViaOverlay": dns_via_overlay
        },
        "external": {
            "publicIp": serde_json::Value::Null,
            "publicIpOrg": serde_json::Value::Null,
            "publicIpLocation": serde_json::Value::Null,
            "targets": external_targets
        },
        "rawEvidenceRefs": ["network-environment-evidence.json"],
        "rawCaptures": raw_captures
    });
    let summary = build_reliability_summary(&evidence);
    let report = build_network_reliability_report(&summary, &evidence);
    let retest = build_network_reliability_retest(&summary);
    let summary_json = serde_json::to_string_pretty(&summary)
        .map_err(|error| format!("Unable to serialize reliability summary: {error}"))?;
    let evidence_json = serde_json::to_string_pretty(&evidence)
        .map_err(|error| format!("Unable to serialize reliability evidence: {error}"))?;

    let output_files = [
        ("network-environment-summary.json", summary_json.clone()),
        ("network-environment-evidence.json", evidence_json.clone()),
        ("network-environment-report.md", report.clone()),
        ("network-environment-retest.md", retest.clone()),
    ];
    for (name, content) in &output_files {
        let path = output_directory.join(name);
        if path.exists() && !is_regular_file(&path) {
            return Err(format!("Reliability output path is not a regular file: {name}"));
        }
        fs::write(&path, content)
            .map_err(|error| format!("Unable to write reliability output {name}: {error}"))?;
    }
    let bundle_path = write_redacted_support_bundle(&output_directory, &output_files, &home)?;

    Ok(NetworkReliabilityRun {
        summary,
        evidence,
        report_markdown: report,
        support_bundle_path: bundle_path.display().to_string(),
        output_directory: output_directory.display().to_string(),
    })
}

#[tauri::command]
async fn run_network_reliability_check(
    execution_state: tauri::State<'_, AuditExecutionState>,
) -> Result<NetworkReliabilityRun, String> {
    execution_state.consume_authorization()?;
    let _guard = execution_state.try_start()?;
    tauri::async_runtime::spawn_blocking(collect_network_reliability)
        .await
        .map_err(|error| format!("Network reliability worker failed: {error}"))?
}

#[tauri::command]
fn open_network_reliability_artifact(kind: String) -> Result<(), String> {
    let directory = latest_lab_path()?.join("08-network-reliability");
    let target = match kind.as_str() {
        "folder" => directory,
        "report" => directory.join("network-environment-report.md"),
        "summary" => directory.join("network-environment-summary.json"),
        "evidence" => directory.join("network-environment-evidence.json"),
        "retest" => directory.join("network-environment-retest.md"),
        "bundle" => directory.join("network-environment-redacted-support-bundle.zip"),
        _ => return Err("Unsupported reliability artifact.".to_string()),
    };
    if kind == "folder" {
        if !is_regular_directory(&target) {
            return Err("Reliability output folder does not exist.".to_string());
        }
    } else if !is_regular_file(&target) {
        return Err("Reliability artifact does not exist.".to_string());
    }
    open_fixed_folder(&target)
}

#[tauri::command]
async fn export_latest_lab_zip() -> Result<ExportResult, String> {
    tauri::async_runtime::spawn_blocking(create_latest_lab_zip)
        .await
        .map_err(|error| format!("ZIP export worker failed: {error}"))?
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AuditExecutionState::default())
        .invoke_handler(tauri::generate_handler![
            check_engine,
            install_bundled_engine,
            list_audit_interfaces,
            authorize_audit,
            run_audit_step,
            run_full_audit,
            run_network_reliability_check,
            read_latest_report,
            read_remediation_tracking,
            save_remediation_tracking,
            read_remediation_pack,
            save_remediation_pack,
            open_latest_lab_folder,
            open_html_report,
            open_excel_report,
            export_latest_lab_zip,
            open_network_reliability_artifact,
            open_engine_folder,
            open_export_folder
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::File,
        os::unix::{fs::symlink, fs::PermissionsExt},
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn every_allowed_step_maps_to_an_expected_script() {
        let steps = [
            AuditStep::InitLab,
            AuditStep::Baseline,
            AuditStep::PassiveAssets,
            AuditStep::ClientIsolation,
            AuditStep::CommonServices,
            AuditStep::SmbPosture,
            AuditStep::GatewayPosture,
            AuditStep::BuildReport,
            AuditStep::LocalNetworkConfig,
            AuditStep::MdnsObservation,
            AuditStep::WebTlsBaseline,
            AuditStep::BuildEnhancedGovernanceReport,
            AuditStep::BuildFormats,
        ];

        let mapped = steps.map(AuditStep::script_name);
        let expected = ENGINE_SCRIPTS.map(|(_, script_name)| script_name);
        assert_eq!(mapped, expected);

        let mapped_ids = steps.map(AuditStep::id);
        let expected_ids = ENGINE_SCRIPTS.map(|(step_id, _)| step_id);
        assert_eq!(mapped_ids, expected_ids);
    }

    #[test]
    fn unknown_step_ids_are_rejected_by_deserialization() {
        let result = serde_json::from_str::<AuditStep>("\"custom_command\"");
        assert!(result.is_err());
    }

    #[test]
    fn executable_check_rejects_symlinks() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after Unix epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("lanpilot-audit-test-{unique}"));
        fs::create_dir(&directory).expect("temporary test directory should be created");

        let script = directory.join("script.sh");
        File::create(&script).expect("temporary script should be created");
        let mut permissions = fs::metadata(&script)
            .expect("temporary script metadata should exist")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&script, permissions).expect("script should be made executable");

        let link = directory.join("linked-script.sh");
        symlink(&script, &link).expect("temporary symlink should be created");

        assert!(is_executable(&script));
        assert!(!is_executable(&link));
        assert!(!is_regular_file(&link));
        assert!(is_regular_directory(&directory));

        fs::remove_dir_all(directory).expect("temporary test directory should be removed");
    }

    #[test]
    fn report_reader_rejects_missing_files_and_symlinks() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after Unix epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("lanpilot-report-test-{unique}"));
        fs::create_dir(&directory).expect("temporary test directory should be created");

        let report = directory.join("report.md");
        fs::write(&report, "expected report").expect("temporary report should be written");
        assert_eq!(
            read_required_file(report.clone()).expect("regular report should be readable"),
            "expected report"
        );

        let link = directory.join("linked-report.md");
        symlink(&report, &link).expect("temporary symlink should be created");
        assert!(read_required_file(link).is_err());
        assert!(read_required_file(directory.join("missing.md")).is_err());

        fs::remove_dir_all(directory).expect("temporary test directory should be removed");
    }

    #[test]
    fn findings_are_parsed_and_counted_from_csv() {
        let csv = "issue_id,severity,asset,category,finding,evidence_file,business_risk,remediation_owner,recommended_action,validation_method,status\nNG-001,High,host-a,Access,Finding A,evidence-a,Risk A,Owner A,Fix A,Validate A,open\nNG-002,Medium,host-b,Service,Finding B,evidence-b,Risk B,Owner B,Fix B,Validate B,open\nNG-003,Low,host-c,Exposure,Finding C,evidence-c,Risk C,Owner C,Fix C,Validate C,closed\n";
        let findings = parse_findings(Some(csv)).expect("valid findings CSV should parse");
        assert_eq!(findings.len(), 3);
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.severity == "High")
                .count(),
            1
        );
        assert_eq!(findings[1].recommended_action, "Fix B");
    }

    #[test]
    fn duplicate_findings_are_counted_once_without_changing_raw_csv() {
        let csv = "issue_id,severity,asset,category,finding,evidence_file,business_risk,remediation_owner,recommended_action,validation_method,status\nNG-001,High,192.168.50.248,SMB,SMB service is reachable from peer client network,evidence-a,Risk A,Owner A,Close SMB,Validate A,open\nNG-002,High,192.168.50.248,SMB,SMB service is reachable from peer client network,evidence-b,Risk A,Owner A,Close SMB,Validate A,open\n";
        let findings = parse_findings(Some(csv)).expect("duplicate findings CSV should parse");
        assert_eq!(findings.len(), 1);
        assert_eq!(csv.matches("SMB service is reachable").count(), 2);
    }

    #[test]
    fn execution_state_allows_only_one_step_at_a_time() {
        let state = AuditExecutionState::default();
        let guard = state
            .try_start()
            .expect("first step should acquire the lock");
        assert!(state.try_start().is_err());

        drop(guard);
        assert!(state.try_start().is_ok());
    }

    #[test]
    fn authorization_is_consumed_once() {
        let state = AuditExecutionState::default();
        assert!(state.consume_authorization().is_err());
        state.authorize();
        assert!(state.consume_authorization().is_ok());
        assert!(state.consume_authorization().is_err());
    }

    #[test]
    fn zip_export_includes_regular_files_and_skips_symlinks() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after Unix epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("lanpilot-zip-test-{unique}"));
        let source = directory.join("source");
        fs::create_dir_all(source.join("report")).expect("temporary directory should be created");
        fs::write(source.join("report/summary.md"), "summary").expect("report should be written");
        symlink(
            source.join("report/summary.md"),
            source.join("report/linked.md"),
        )
        .expect("temporary symlink should be created");
        let zip_path = directory.join("export.zip");
        let zip_file = fs::File::create(&zip_path).expect("ZIP file should be created");
        let mut writer = zip::ZipWriter::new(zip_file);
        add_directory_to_zip(&mut writer, &source, &source)
            .expect("temporary directory should be zipped");
        writer.finish().expect("ZIP should be finished");

        let zip_file = fs::File::open(&zip_path).expect("ZIP should be readable");
        let mut archive = zip::ZipArchive::new(zip_file).expect("ZIP should be valid");
        assert!(archive.by_name("report/summary.md").is_ok());
        assert!(archive.by_name("report/linked.md").is_err());

        fs::remove_dir_all(directory).expect("temporary test directory should be removed");
    }

    fn sample_remediation_pack(status: &str) -> RemediationPack {
        RemediationPack {
            id: "pack-1".to_string(),
            generated_at: "2026-06-14T00:00:00Z".to_string(),
            lab_directory: "/tmp/lab".to_string(),
            language: "en".to_string(),
            risk_summary: std::collections::HashMap::from([("High".to_string(), 1)]),
            findings: Vec::new(),
            tickets: vec![RemediationTicket {
                id: "RMT-001".to_string(),
                finding_fingerprint: "fingerprint".to_string(),
                severity: "High".to_string(),
                asset: "192.168.1.1".to_string(),
                category: "Gateway".to_string(),
                localized_finding: "Observed service exposure.".to_string(),
                localized_recommended_action: "Review manually.".to_string(),
                owner: String::new(),
                due_date: String::new(),
                priority: "High".to_string(),
                status: status.to_string(),
                business_justification: String::new(),
                manual_steps: vec!["Assign an authorized administrator.".to_string()],
                validation_steps: vec!["Run an authorized retest.".to_string()],
                rollback_considerations: vec!["Document a rollback plan.".to_string()],
                evidence_references: vec!["04-risk/network-issues-register.csv".to_string()],
                notes: String::new(),
            }],
            verification_plan: vec!["Run an authorized retest.".to_string()],
            acceptance_records: Vec::new(),
        }
    }

    #[test]
    fn remediation_pack_writes_only_fixed_structured_artifacts() {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let directory = std::env::temp_dir().join(format!("lanpilot-remediation-test-{unique}"));
        write_remediation_pack(&directory, &sample_remediation_pack("open"))
            .expect("valid remediation pack should be written");
        for name in [
            "remediation-pack.json", "remediation-tickets.csv", "remediation-playbook.md",
            "remediation-verification-plan.md", "remediation-acceptance-records.csv",
        ] {
            assert!(is_regular_file(&directory.join(name)), "{name} should exist");
        }
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 5);
        fs::remove_dir_all(directory).expect("temporary test directory should be removed");
    }

    #[test]
    fn remediation_pack_rejects_unknown_status() {
        assert!(validate_remediation_pack(&sample_remediation_pack("unknown_status")).is_err());
    }

    #[test]
    fn engine_install_rejects_unsafe_destination() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after Unix epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("lanpilot-engine-test-{unique}"));
        let source = directory.join("source");
        let destination = directory.join("destination");
        fs::create_dir_all(&source).expect("source directory should be created");
        fs::write(source.join("VERSION"), BUNDLED_ENGINE_VERSION)
            .expect("version should be written");
        fs::create_dir_all(&directory).expect("test directory should exist");
        fs::write(&destination, "not a directory").expect("unsafe destination should be written");
        assert!(copy_engine_directory(&source, &destination).is_err());
        fs::remove_dir_all(directory).expect("temporary test directory should be removed");
    }

    #[test]
    fn engine_manifest_detects_changes_and_unlisted_files() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after Unix epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("lanpilot-engine-manifest-{unique}"));
        fs::create_dir_all(&directory).expect("temporary directory should be created");
        fs::write(directory.join("VERSION"), "1.2.0\n").expect("version should be written");
        let hash = format!("{:x}", Sha256::digest(b"1.2.0\n"));
        fs::write(
            directory.join("ENGINE_SHA256SUMS.txt"),
            format!("{hash}  VERSION\n"),
        )
        .expect("manifest should be written");
        assert!(verify_engine_manifest(&directory).is_ok());

        fs::write(directory.join("VERSION"), "changed\n").expect("version should change");
        assert!(verify_engine_manifest(&directory).is_err());
        fs::write(directory.join("VERSION"), "1.2.0\n").expect("version should be restored");
        fs::write(directory.join("extra.txt"), "unexpected").expect("extra file should be written");
        assert!(verify_engine_manifest(&directory).is_err());

        fs::remove_dir_all(directory).expect("temporary directory should be removed");
    }

    #[test]
    fn engine_manifest_rejects_unsafe_and_duplicate_paths() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after Unix epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("lanpilot-engine-paths-{unique}"));
        fs::create_dir_all(&directory).expect("temporary directory should be created");
        fs::write(directory.join("VERSION"), "1.2.0\n").expect("version should be written");
        let hash = format!("{:x}", Sha256::digest(b"1.2.0\n"));

        fs::write(
            directory.join("ENGINE_SHA256SUMS.txt"),
            format!("{hash}  ../VERSION\n"),
        )
        .expect("unsafe manifest should be written");
        assert!(verify_engine_manifest(&directory).is_err());

        fs::write(
            directory.join("ENGINE_SHA256SUMS.txt"),
            format!("{hash}  VERSION\n{hash}  VERSION\n"),
        )
        .expect("duplicate manifest should be written");
        assert!(verify_engine_manifest(&directory).is_err());

        fs::remove_dir_all(directory).expect("temporary test directory should be removed");
    }

    #[test]
    fn engine_path_is_fixed_under_application_support() {
        let path = engine_path().expect("engine path should resolve");
        assert!(path.ends_with("Library/Application Support/LANPilot Audit/lanpilot-audit"));
    }

    #[test]
    fn reliability_support_redaction_masks_local_identifiers() {
        let redacted = redact_text_for_support_bundle(
            "/Users/alice/lanpilot 192.168.50.10 10.0.0.1 aa:bb:cc:dd:ee:ff",
            Path::new("/Users/alice"),
        );
        assert!(redacted.contains("/Users/demo"));
        assert!(!redacted.contains("/Users/alice"));
        assert!(!redacted.contains("192.168.50.10"));
        assert!(!redacted.contains("10.0.0.1"));
        assert!(!redacted.contains("aa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn reliability_artifact_opener_rejects_unknown_kind() {
        assert!(open_network_reliability_artifact("freeform".to_string()).is_err());
    }

    #[test]
    fn reliability_summary_contains_required_fields() {
        let evidence = serde_json::json!({
            "profile": "Home LAN",
            "physicalLan": {
                "activeInterface": "en0",
                "interfaceKind": "wifi",
                "ipv4": "192.0.2.20",
                "dhcpOk": true,
                "gatewayIp": "192.0.2.1",
                "gatewayPingLossPct": 0,
                "gatewayPingAvgMs": 3,
                "gatewayDnsMs": 20,
                "selfAssignedAddress": false
            },
            "localControlPlane": {
                "systemDnsServers": ["192.0.2.1"],
                "scopedResolvers": [],
                "resolverSummary": "Gateway DNS",
                "listeningServices": []
            },
            "overlay": {
                "defaultRouteInterface": "en0",
                "utunInterfaces": [],
                "stashDetected": false,
                "tailscaleRunning": false,
                "multipleOverlayComponents": false,
                "dnsViaOverlay": false
            },
            "external": {
                "targets": [
                    { "group": "apple", "url": "https://www.apple.com", "totalMs": 800, "status": 200, "failed": false }
                ]
            }
        });
        let summary = build_reliability_summary(&evidence);
        for key in [
            "overallStatus",
            "physicalLanStatus",
            "dnsStatus",
            "overlayStatus",
            "externalPathStatus",
            "faultDomain",
            "faultPoint",
            "impact",
            "evidence",
            "remediationAdvice",
            "retestPlan",
            "rawEvidenceRefs",
        ] {
            assert!(summary.get(key).is_some(), "{key} should exist");
        }
    }
}
