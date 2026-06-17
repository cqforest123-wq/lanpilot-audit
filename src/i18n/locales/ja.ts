import type { Messages } from "../types";

export const ja: Messages = {
  appName: "LANPilot Audit", navRun: "監査を実行", navReport: "レポート", navExport: "エクスポート", navSettings: "設定",
  landingEyebrow: "承認済みネットワークガバナンス監査", landingTitle: "承認された一つの流れで、証跡・所見・レポート・エクスポートを完了。",
  landingDescription: "LANPilot は承認された13個のローカルチェックを固定順序で実行し、失敗時には直ちに停止します。",
  startAudit: "承認済み監査を開始", latestReport: "最新レポートを表示", authorization: "承認確認",
  authorizationDescription: "承認済みプロジェクトを記録し、すべての安全境界を確認してください。", projectName: "プロジェクト名",
  site: "サイト / 組織", notes: "メモ", confirmAuthorization: "承認を確認", cancel: "キャンセル",
  engineSetup: "エンジン設定", installEngine: "内蔵エンジンをインストール", updateEngine: "内蔵エンジンを更新",
  continueInterface: "インターフェース確認へ進む", interface: "インターフェース", continueRun: "実行へ進む",
  runAudit: "監査を実行", runFullAudit: "完全監査を実行", stopOnFailure: "失敗時に停止", viewReport: "レポートを表示",
  report: "レポート", export: "エクスポート", exportZip: "ZIP をエクスポート", openExportFolder: "エクスポートフォルダを開く",
  settings: "設定と情報", language: "言語", unknown: "不明", missingFiles: "不足しているレポートファイル",
  limitedMode: "制限モード", nmapUnavailable: "nmap を利用できません。依存するチェックはスキップされます。",
  safetyBoundary: "安全境界", privacy: "ローカル優先、クラウド送信なし",
  pointInTime: "所見は、現在の ARP キャッシュ、ICMP 到達性、低強度の一般サービスチェックに基づく時点観測です。",
  high: "高", medium: "中", low: "低", reachableClients: "到達可能なクライアント", unreachableClients: "到達不能なクライアント",
  openServiceHosts: "オープンサービスのホスト", gatewayPosture: "ゲートウェイ状態", riskRegister: "リスク台帳",
  remediationRoadmap: "改善ロードマップ", executiveSummary: "エグゼクティブサマリー", technicalReport: "技術レポート",
  pending: "待機中", running: "実行中", success: "成功", failed: "失敗", skipped: "スキップ",
};
