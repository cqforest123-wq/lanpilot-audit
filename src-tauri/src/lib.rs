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
            read_latest_report,
            read_remediation_tracking,
            save_remediation_tracking,
            read_remediation_pack,
            save_remediation_pack,
            open_latest_lab_folder,
            open_html_report,
            open_excel_report,
            export_latest_lab_zip,
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
}
