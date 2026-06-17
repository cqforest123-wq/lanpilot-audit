import type { Messages } from "../types";

export const zhTW: Messages = {
  appName: "LANPilot Audit", navRun: "執行稽核", navReport: "報告", navExport: "匯出", navSettings: "設定",
  landingEyebrow: "授權網路治理稽核", landingTitle: "一次授權流程，完成證據、發現、報告與匯出。",
  landingDescription: "LANPilot 依固定順序執行八項已核准的本機檢查，並在失敗時立即停止。",
  startAudit: "開始授權稽核", latestReport: "檢視最新報告", authorization: "授權確認",
  authorizationDescription: "記錄已授權的專案並確認所有安全邊界。", projectName: "專案名稱",
  site: "站點 / 組織", notes: "備註", confirmAuthorization: "確認授權", cancel: "取消",
  engineSetup: "引擎設定", installEngine: "安裝內建引擎", updateEngine: "更新內建引擎",
  continueInterface: "繼續至介面確認", interface: "介面確認", continueRun: "繼續至執行",
  runAudit: "執行稽核", runFullAudit: "執行完整稽核", stopOnFailure: "失敗即停止", viewReport: "檢視報告",
  report: "報告", export: "匯出", exportZip: "匯出 ZIP", openExportFolder: "開啟匯出資料夾",
  settings: "設定與關於", language: "語言", unknown: "未知", missingFiles: "缺少報告檔案",
  limitedMode: "受限模式", nmapUnavailable: "nmap 無法使用，相關檢查將略過。",
  safetyBoundary: "安全邊界", privacy: "本機優先，不上傳雲端",
  pointInTime: "發現是基於目前 ARP 快取、ICMP 可達性及低強度常用服務檢查的時點觀察。",
  high: "高", medium: "中", low: "低", reachableClients: "可達用戶端", unreachableClients: "不可達用戶端",
  openServiceHosts: "開放服務主機", gatewayPosture: "閘道狀態", riskRegister: "風險台帳",
  remediationRoadmap: "修正路線圖", executiveSummary: "管理摘要", technicalReport: "技術報告",
  pending: "待處理", running: "執行中", success: "成功", failed: "失敗", skipped: "已略過",
};
