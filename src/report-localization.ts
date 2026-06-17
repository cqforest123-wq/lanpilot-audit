import type { Locale } from "./i18n/types";

export interface ReportFinding {
  severity: string;
  asset: string;
  category: string;
  finding: string;
  recommended_action: string;
  status: string;
}

export interface LocalizedFinding extends ReportFinding {
  localizedCategory: string;
  localizedFinding: string;
  localizedRecommendedAction: string;
  localizedStatus: string;
  matched: boolean;
}

interface ReportCopy {
  latestLocalAudit: string;
  description: string;
  pointInTime: string;
  localizedView: string;
  rawView: string;
  rawEvidence: string;
  rawPreserved: string;
  executiveSummary: string;
  executiveBody: string;
  riskRegister: string;
  remediationRoadmap: string;
  generatedAt: string;
  labDirectory: string;
  riskSummary: string;
  severity: string;
  asset: string;
  category: string;
  finding: string;
  recommendedAction: string;
  status: string;
  noFindings: string;
  raw: string;
  viewOriginal: string;
  unknown: string;
  servicesObserved: string;
  noServicesObserved: string;
  daysHigh: string;
  daysMedium: string;
  daysLow: string;
  recommendationPrefix: string;
  otherCategory: string;
  unmatchedFinding: string;
  openStatus: string;
  closedStatus: string;
}

const en: ReportCopy = {
  latestLocalAudit: "Latest local audit", description: "Structured findings and point-in-time evidence from the latest audit workspace.",
  pointInTime: "Findings are point-in-time observations based on the current ARP cache, ICMP reachability, and low-intensity common service checks. They do not represent a permanent network state.",
  localizedView: "Localized View", rawView: "Raw Evidence", rawEvidence: "Raw Evidence",
  rawPreserved: "Raw evidence is preserved in its original language.", executiveSummary: "Executive Summary",
  executiveBody: "This report summarizes authorized network governance observations from the latest local audit workspace.",
  riskRegister: "Risk Register", remediationRoadmap: "Remediation Roadmap", generatedAt: "Generated at", labDirectory: "Lab directory",
  riskSummary: "Risk summary", severity: "Severity", asset: "Asset", category: "Category", finding: "Finding",
  recommendedAction: "Recommended action", status: "Status", noFindings: "No structured findings available.", raw: "raw",
  viewOriginal: "View original", unknown: "Unknown", servicesObserved: "Services observed", noServicesObserved: "No open services observed",
  daysHigh: "0-7 days", daysMedium: "8-30 days", daysLow: "31-90 days", recommendationPrefix: "Recommendation",
  otherCategory: "Other", unmatchedFinding: "See the raw evidence for this unmatched finding.", openStatus: "Open", closedStatus: "Closed",
};

const copies: Record<Locale, ReportCopy> = {
  en,
  "zh-CN": {
    latestLocalAudit: "最近一次本地审计", description: "最近一次审计工作区中的结构化发现与时点证据。",
    pointInTime: "发现结果是基于当前 ARP 缓存、ICMP 可达性和低强度常用服务检查的时点观察，不代表网络的永久状态。",
    localizedView: "本地化视图", rawView: "原始证据", rawEvidence: "原始证据", rawPreserved: "原始证据按生成时的原文保留。",
    executiveSummary: "管理摘要", executiveBody: "本报告汇总最近一次本地审计工作区中的授权网络治理观察结果。",
    riskRegister: "风险台账", remediationRoadmap: "整改路线图", generatedAt: "生成时间", labDirectory: "审计目录",
    riskSummary: "风险摘要", severity: "严重程度", asset: "资产", category: "类别", finding: "发现",
    recommendedAction: "建议措施", status: "状态", noFindings: "暂无结构化发现。", raw: "原文",
    viewOriginal: "查看原文", unknown: "未知", servicesObserved: "发现开放服务", noServicesObserved: "未发现开放服务",
    daysHigh: "0-7 天", daysMedium: "8-30 天", daysLow: "31-90 天", recommendationPrefix: "建议",
    otherCategory: "其他", unmatchedFinding: "此发现尚无本地化规则，请在原始证据中查看原文。", openStatus: "待处理", closedStatus: "已关闭",
  },
  "zh-TW": {
    latestLocalAudit: "最近一次本機稽核", description: "最近一次稽核工作區中的結構化發現與時點證據。",
    pointInTime: "發現結果是基於目前 ARP 快取、ICMP 可達性及低強度常用服務檢查的時點觀察，不代表網路的永久狀態。",
    localizedView: "本地化檢視", rawView: "原始證據", rawEvidence: "原始證據", rawPreserved: "原始證據依生成時的原文保留。",
    executiveSummary: "管理摘要", executiveBody: "本報告彙總最近一次本機稽核工作區中的授權網路治理觀察結果。",
    riskRegister: "風險台帳", remediationRoadmap: "修正路線圖", generatedAt: "生成時間", labDirectory: "稽核目錄",
    riskSummary: "風險摘要", severity: "嚴重程度", asset: "資產", category: "類別", finding: "發現",
    recommendedAction: "建議措施", status: "狀態", noFindings: "暫無結構化發現。", raw: "原文",
    viewOriginal: "檢視原文", unknown: "未知", servicesObserved: "發現開放服務", noServicesObserved: "未發現開放服務",
    daysHigh: "0-7 天", daysMedium: "8-30 天", daysLow: "31-90 天", recommendationPrefix: "建議",
    otherCategory: "其他", unmatchedFinding: "此發現尚無本地化規則，請在原始證據中檢視原文。", openStatus: "待處理", closedStatus: "已關閉",
  },
  ja: {
    latestLocalAudit: "最新のローカル監査", description: "最新の監査ワークスペースから得られた構造化された所見と時点証跡です。",
    pointInTime: "所見は現在の ARP キャッシュ、ICMP 到達性、低強度の一般サービスチェックに基づく時点観測であり、恒久的なネットワーク状態を示すものではありません。",
    localizedView: "ローカライズ表示", rawView: "原始証跡", rawEvidence: "原始証跡", rawPreserved: "原始証跡は生成時の言語のまま保持されます。",
    executiveSummary: "エグゼクティブサマリー", executiveBody: "このレポートは、最新のローカル監査ワークスペースから得られた承認済みネットワークガバナンスの観測結果をまとめたものです。",
    riskRegister: "リスク台帳", remediationRoadmap: "改善ロードマップ", generatedAt: "生成日時", labDirectory: "監査ディレクトリ",
    riskSummary: "リスク概要", severity: "重大度", asset: "資産", category: "カテゴリ", finding: "所見",
    recommendedAction: "推奨対応", status: "状態", noFindings: "構造化された所見はありません。", raw: "原文",
    viewOriginal: "原文を表示", unknown: "不明", servicesObserved: "サービスを検出", noServicesObserved: "オープンサービスなし",
    daysHigh: "0-7日", daysMedium: "8-30日", daysLow: "31-90日", recommendationPrefix: "推奨対応",
    otherCategory: "その他", unmatchedFinding: "この所見にはローカライズ規則がありません。原始証跡で原文を確認してください。", openStatus: "未対応", closedStatus: "完了",
  },
  ko: {
    latestLocalAudit: "최신 로컬 감사", description: "최신 감사 작업 공간의 구조화된 발견 사항과 시점 증거입니다.",
    pointInTime: "발견 사항은 현재 ARP 캐시, ICMP 도달 가능성 및 저강도 일반 서비스 검사를 기반으로 한 시점 관찰이며 영구적인 네트워크 상태를 의미하지 않습니다.",
    localizedView: "현지화 보기", rawView: "원시 증거", rawEvidence: "원시 증거", rawPreserved: "원시 증거는 생성 당시의 원문 언어로 보존됩니다.",
    executiveSummary: "요약 보고서", executiveBody: "이 보고서는 최신 로컬 감사 작업 공간의 승인된 네트워크 거버넌스 관찰 결과를 요약합니다.",
    riskRegister: "위험 대장", remediationRoadmap: "개선 로드맵", generatedAt: "생성 시간", labDirectory: "감사 디렉터리",
    riskSummary: "위험 요약", severity: "심각도", asset: "자산", category: "범주", finding: "발견 사항",
    recommendedAction: "권장 조치", status: "상태", noFindings: "구조화된 발견 사항이 없습니다.", raw: "원문",
    viewOriginal: "원문 보기", unknown: "알 수 없음", servicesObserved: "서비스 발견됨", noServicesObserved: "열린 서비스 없음",
    daysHigh: "0-7일", daysMedium: "8-30일", daysLow: "31-90일", recommendationPrefix: "권장 조치",
    otherCategory: "기타", unmatchedFinding: "이 발견 사항에는 현지화 규칙이 없습니다. 원시 증거에서 원문을 확인하세요.", openStatus: "미처리", closedStatus: "완료",
  },
  de: { ...en, latestLocalAudit:"Letztes lokales Audit",description:"Strukturierte Befunde und zeitpunktbezogene Nachweise aus dem letzten Audit-Arbeitsbereich.",pointInTime:"Befunde sind zeitpunktbezogene Beobachtungen und stellen keinen dauerhaften Netzwerkzustand dar.",localizedView:"Lokalisierte Ansicht",rawView:"Rohdaten",rawEvidence:"Rohdaten",rawPreserved:"Rohdaten bleiben in ihrer Originalsprache erhalten.",executiveSummary:"Management-Zusammenfassung",executiveBody:"Dieser Bericht fasst autorisierte Netzwerk-Governance-Beobachtungen des letzten lokalen Audits zusammen.",riskRegister:"Risikoregister",remediationRoadmap:"Maßnahmenplan",generatedAt:"Erstellt am",labDirectory:"Audit-Verzeichnis",riskSummary:"Risikoübersicht",severity:"Schweregrad",asset:"Asset",category:"Kategorie",finding:"Befund",recommendedAction:"Empfohlene Maßnahme",status:"Status",noFindings:"Keine strukturierten Befunde vorhanden.",raw:"Original",viewOriginal:"Original anzeigen",unknown:"Unbekannt",servicesObserved:"Dienste erkannt",noServicesObserved:"Keine offenen Dienste erkannt",daysHigh:"0-7 Tage",daysMedium:"8-30 Tage",daysLow:"31-90 Tage",recommendationPrefix:"Empfehlung" },
  fr: { ...en, latestLocalAudit:"Dernier audit local",description:"Constats structurés et preuves ponctuelles du dernier espace d’audit.",pointInTime:"Les constats sont des observations ponctuelles et ne représentent pas un état permanent du réseau.",localizedView:"Vue localisée",rawView:"Preuves originales",rawEvidence:"Preuves originales",rawPreserved:"Les preuves originales sont conservées dans leur langue d’origine.",executiveSummary:"Résumé exécutif",executiveBody:"Ce rapport résume les observations autorisées de gouvernance réseau du dernier audit local.",riskRegister:"Registre des risques",remediationRoadmap:"Feuille de route de remédiation",generatedAt:"Généré le",labDirectory:"Répertoire d’audit",riskSummary:"Résumé des risques",severity:"Sévérité",asset:"Actif",category:"Catégorie",finding:"Constat",recommendedAction:"Action recommandée",status:"État",noFindings:"Aucun constat structuré disponible.",raw:"original",viewOriginal:"Voir l’original",unknown:"Inconnu",servicesObserved:"Services observés",noServicesObserved:"Aucun service ouvert observé",daysHigh:"0-7 jours",daysMedium:"8-30 jours",daysLow:"31-90 jours",recommendationPrefix:"Recommandation" },
  es: { ...en, latestLocalAudit:"Última auditoría local",description:"Hallazgos estructurados y evidencia puntual del último espacio de auditoría.",pointInTime:"Los hallazgos son observaciones puntuales y no representan un estado permanente de la red.",localizedView:"Vista localizada",rawView:"Evidencia original",rawEvidence:"Evidencia original",rawPreserved:"La evidencia original se conserva en su idioma original.",executiveSummary:"Resumen ejecutivo",executiveBody:"Este informe resume las observaciones autorizadas de gobierno de red de la última auditoría local.",riskRegister:"Registro de riesgos",remediationRoadmap:"Hoja de ruta de corrección",generatedAt:"Generado",labDirectory:"Directorio de auditoría",riskSummary:"Resumen de riesgos",severity:"Severidad",asset:"Activo",category:"Categoría",finding:"Hallazgo",recommendedAction:"Acción recomendada",status:"Estado",noFindings:"No hay hallazgos estructurados.",raw:"original",viewOriginal:"Ver original",unknown:"Desconocido",servicesObserved:"Servicios observados",noServicesObserved:"No se observaron servicios abiertos",daysHigh:"0-7 días",daysMedium:"8-30 días",daysLow:"31-90 días",recommendationPrefix:"Recomendación" },
  "pt-BR": { ...en, latestLocalAudit:"Auditoria local mais recente",description:"Achados estruturados e evidências pontuais do espaço de auditoria mais recente.",pointInTime:"Os achados são observações pontuais e não representam um estado permanente da rede.",localizedView:"Visão localizada",rawView:"Evidências originais",rawEvidence:"Evidências originais",rawPreserved:"As evidências originais são preservadas no idioma original.",executiveSummary:"Resumo executivo",executiveBody:"Este relatório resume observações autorizadas de governança de rede da auditoria local mais recente.",riskRegister:"Registro de riscos",remediationRoadmap:"Roteiro de correção",generatedAt:"Gerado em",labDirectory:"Diretório de auditoria",riskSummary:"Resumo de riscos",severity:"Severidade",asset:"Ativo",category:"Categoria",finding:"Achado",recommendedAction:"Ação recomendada",status:"Status",noFindings:"Nenhum achado estruturado disponível.",raw:"original",viewOriginal:"Ver original",unknown:"Desconhecido",servicesObserved:"Serviços observados",noServicesObserved:"Nenhum serviço aberto observado",daysHigh:"0-7 dias",daysMedium:"8-30 dias",daysLow:"31-90 dias",recommendationPrefix:"Recomendação" },
  it: { ...en, latestLocalAudit:"Ultimo audit locale",description:"Risultati strutturati ed evidenze puntuali dall’ultimo spazio di audit.",pointInTime:"I risultati sono osservazioni puntuali e non rappresentano uno stato permanente della rete.",localizedView:"Vista localizzata",rawView:"Evidenze originali",rawEvidence:"Evidenze originali",rawPreserved:"Le evidenze originali vengono conservate nella lingua originale.",executiveSummary:"Riepilogo esecutivo",executiveBody:"Questo rapporto riassume le osservazioni autorizzate di governance della rete dell’ultimo audit locale.",riskRegister:"Registro dei rischi",remediationRoadmap:"Piano di correzione",generatedAt:"Generato il",labDirectory:"Directory di audit",riskSummary:"Riepilogo rischi",severity:"Gravità",asset:"Risorsa",category:"Categoria",finding:"Risultato",recommendedAction:"Azione consigliata",status:"Stato",noFindings:"Nessun risultato strutturato disponibile.",raw:"originale",viewOriginal:"Mostra originale",unknown:"Sconosciuto",servicesObserved:"Servizi osservati",noServicesObserved:"Nessun servizio aperto osservato",daysHigh:"0-7 giorni",daysMedium:"8-30 giorni",daysLow:"31-90 giorni",recommendationPrefix:"Raccomandazione" },
  nl: { ...en, latestLocalAudit:"Laatste lokale audit",description:"Gestructureerde bevindingen en momentopnamen uit de laatste auditwerkruimte.",pointInTime:"Bevindingen zijn momentopnamen en vertegenwoordigen geen permanente netwerkstatus.",localizedView:"Gelokaliseerde weergave",rawView:"Origineel bewijs",rawEvidence:"Origineel bewijs",rawPreserved:"Origineel bewijs blijft in de oorspronkelijke taal behouden.",executiveSummary:"Managementsamenvatting",executiveBody:"Dit rapport vat geautoriseerde netwerkgovernance-observaties uit de laatste lokale audit samen.",riskRegister:"Risicoregister",remediationRoadmap:"Herstelplan",generatedAt:"Gegenereerd op",labDirectory:"Auditmap",riskSummary:"Risico-overzicht",severity:"Ernst",asset:"Asset",category:"Categorie",finding:"Bevinding",recommendedAction:"Aanbevolen actie",status:"Status",noFindings:"Geen gestructureerde bevindingen beschikbaar.",raw:"origineel",viewOriginal:"Origineel bekijken",unknown:"Onbekend",servicesObserved:"Diensten waargenomen",noServicesObserved:"Geen open diensten waargenomen",daysHigh:"0-7 dagen",daysMedium:"8-30 dagen",daysLow:"31-90 dagen",recommendationPrefix:"Aanbeveling" },
};

export const reportCopy = (locale: Locale): ReportCopy => copies[locale];

export function deduplicateFindings(findings: ReportFinding[]): ReportFinding[] {
  const seen = new Set<string>();
  return findings.filter((finding) => {
    const fingerprint = [finding.severity, finding.asset, finding.category, finding.finding, finding.recommended_action]
      .map((value) => value.trim().toLowerCase())
      .join("\u001f");
    if (seen.has(fingerprint)) return false;
    seen.add(fingerprint);
    return true;
  });
}

const localizedRules: Record<Locale, Record<string, [string, string]>> = {
  en: {
    web: ["Client asset web service {port} is reachable from the current network position.", "Confirm the business purpose and restrict or remove unnecessary service exposure."],
    smb: ["SMB service is reachable from the peer client network position.", "Close unnecessary SMB exposure; when SMB is required, segment the network and enforce SMB signing."],
    remote: ["Remote administration service {port} is reachable from the current network position.", "Allow remote administration only from approved management networks and enforce strong access controls."],
    signing: ["SMB signing is not enforced on one or more SMB hosts.", "Enforce SMB signing where business-compatible and complete compatibility validation."],
    gateway: ["The default gateway exposes management or infrastructure services to the local client network.", "Confirm each exposed service is necessary, restrict management interface access, and document ownership and firmware status."],
    isolation: ["{count} client asset(s) responded to single-packet ICMP from the peer network position.", "Review wireless and wired client isolation policies, VLAN ACLs, and firewall rules."],
  },
  "zh-CN": {
    web: ["客户端资产的 {port} Web 服务可从当前网络位置访问。", "确认业务用途，并限制或移除不必要的服务暴露。"],
    smb: ["SMB 服务可从同一客户端网络位置访问。", "关闭不必要的 SMB 暴露；如业务需要 SMB，应进行网络分段并强制 SMB 签名。"],
    remote: ["远程管理服务 {port} 可从当前网络位置访问。", "仅允许经批准的管理网段访问远程管理服务，并执行强访问控制。"],
    signing: ["一个或多个 SMB 主机未强制启用 SMB 签名。", "在业务兼容的前提下强制启用 SMB 签名，并完成兼容性验证。"],
    gateway: ["默认网关向本地客户端网络暴露管理或基础设施服务。", "确认每项暴露服务的必要性，限制管理接口访问范围，并记录负责人和固件状态。"],
    isolation: ["有 {count} 个客户端资产对来自同一网络位置的单包 ICMP 探测有响应。", "检查无线和有线客户端隔离策略、VLAN ACL 与防火墙规则。"],
  },
  "zh-TW": {
    web: ["用戶端資產的 {port} Web 服務可從目前網路位置存取。", "確認業務用途，並限制或移除不必要的服務暴露。"],
    smb: ["SMB 服務可從同一用戶端網路位置存取。", "關閉不必要的 SMB 暴露；如業務需要 SMB，應進行網路分段並強制 SMB 簽章。"],
    remote: ["遠端管理服務 {port} 可從目前網路位置存取。", "僅允許經核准的管理網段存取遠端管理服務，並執行強式存取控制。"],
    signing: ["一個或多個 SMB 主機未強制啟用 SMB 簽章。", "在業務相容的前提下強制啟用 SMB 簽章，並完成相容性驗證。"],
    gateway: ["預設閘道向本地用戶端網路暴露管理或基礎設施服務。", "確認每項暴露服務的必要性，限制管理介面存取範圍，並記錄負責人與韌體狀態。"],
    isolation: ["有 {count} 個用戶端資產對來自同一網路位置的單包 ICMP 探測有回應。", "檢查無線及有線用戶端隔離策略、VLAN ACL 與防火牆規則。"],
  },
  ja: {
    web: ["クライアント資産の {port} Web サービスに現在のネットワーク位置から到達できます。", "業務用途を確認し、不要なサービス公開を制限または削除してください。"],
    smb: ["同一クライアントネットワーク位置から SMB サービスに到達できます。", "不要な SMB 公開を停止し、必要な場合はネットワークを分離して SMB 署名を強制してください。"],
    remote: ["リモート管理サービス {port} に現在のネットワーク位置から到達できます。", "承認済み管理ネットワークからのみアクセスを許可し、強力なアクセス制御を実施してください。"],
    signing: ["1台以上の SMB ホストで SMB 署名が強制されていません。", "業務互換性を確認した上で SMB 署名を強制し、互換性検証を完了してください。"],
    gateway: ["デフォルトゲートウェイが管理またはインフラサービスをローカルクライアントネットワークに公開しています。", "各サービスの必要性を確認し、管理インターフェースへのアクセスを制限して、担当者とファームウェア状態を記録してください。"],
    isolation: ["{count} 台のクライアント資産が同一ネットワーク位置からの単一パケット ICMP に応答しました。", "無線・有線クライアント分離ポリシー、VLAN ACL、ファイアウォールルールを確認してください。"],
  },
  ko: {
    web: ["클라이언트 자산의 {port} 웹 서비스에 현재 네트워크 위치에서 접근할 수 있습니다.", "업무 용도를 확인하고 불필요한 서비스 노출을 제한하거나 제거하세요."],
    smb: ["동일한 클라이언트 네트워크 위치에서 SMB 서비스에 접근할 수 있습니다.", "불필요한 SMB 노출을 닫고, 필요한 경우 네트워크를 분리하고 SMB 서명을 강제하세요."],
    remote: ["원격 관리 서비스 {port}에 현재 네트워크 위치에서 접근할 수 있습니다.", "승인된 관리 네트워크에서만 접근을 허용하고 강력한 접근 제어를 적용하세요."],
    signing: ["하나 이상의 SMB 호스트에서 SMB 서명이 강제되지 않습니다.", "업무 호환성을 확인한 후 SMB 서명을 강제하고 호환성 검증을 완료하세요."],
    gateway: ["기본 게이트웨이가 관리 또는 인프라 서비스를 로컬 클라이언트 네트워크에 노출합니다.", "각 노출 서비스의 필요성을 확인하고 관리 인터페이스 접근을 제한하며 담당자와 펌웨어 상태를 기록하세요."],
    isolation: ["{count}개의 클라이언트 자산이 동일 네트워크 위치의 단일 패킷 ICMP에 응답했습니다.", "무선 및 유선 클라이언트 격리 정책, VLAN ACL, 방화벽 규칙을 검토하세요."],
  },
  de: {
    web:["Der Webdienst {port} eines Client-Assets ist von der aktuellen Netzwerkposition erreichbar.","Geschäftszweck bestätigen und unnötige Dienstfreigaben einschränken oder entfernen."],smb:["Der SMB-Dienst ist aus dem Client-Netzwerk erreichbar.","Unnötige SMB-Freigaben schließen; falls erforderlich, Netzwerk segmentieren und SMB-Signierung erzwingen."],remote:["Der Remoteverwaltungsdienst {port} ist erreichbar.","Zugriff nur aus genehmigten Verwaltungsnetzen zulassen und starke Zugriffskontrollen erzwingen."],signing:["SMB-Signierung wird auf mindestens einem SMB-Host nicht erzwungen.","SMB-Signierung nach Kompatibilitätsprüfung erzwingen."],gateway:["Das Standard-Gateway stellt Verwaltungs- oder Infrastrukturdienste im lokalen Client-Netz bereit.","Notwendigkeit prüfen, Verwaltungszugriff beschränken und Verantwortliche sowie Firmwarestatus dokumentieren."],isolation:["{count} Client-Assets antworteten auf ein einzelnes ICMP-Paket aus dem Peer-Netz.","Client-Isolierung, VLAN-ACLs und Firewallregeln prüfen."],
  },
  fr: {
    web:["Le service Web {port} d’un actif client est accessible depuis la position réseau actuelle.","Confirmer l’usage métier et limiter ou supprimer toute exposition inutile."],smb:["Le service SMB est accessible depuis le réseau client pair.","Fermer l’exposition SMB inutile ; si nécessaire, segmenter le réseau et imposer la signature SMB."],remote:["Le service d’administration distante {port} est accessible.","Autoriser uniquement les réseaux d’administration approuvés et appliquer des contrôles d’accès forts."],signing:["La signature SMB n’est pas imposée sur un ou plusieurs hôtes SMB.","Imposer la signature SMB après validation de compatibilité."],gateway:["La passerelle par défaut expose des services de gestion ou d’infrastructure au réseau client local.","Confirmer la nécessité, limiter l’accès de gestion et documenter le responsable et le micrologiciel."],isolation:["{count} actifs clients ont répondu à un paquet ICMP unique depuis le réseau pair.","Vérifier l’isolation client, les ACL VLAN et les règles de pare-feu."],
  },
  es: {
    web:["El servicio web {port} de un activo cliente es accesible desde la posición de red actual.","Confirmar el uso empresarial y limitar o eliminar la exposición innecesaria."],smb:["El servicio SMB es accesible desde la red cliente par.","Cerrar la exposición SMB innecesaria; si se necesita, segmentar la red y exigir firma SMB."],remote:["El servicio de administración remota {port} es accesible.","Permitir acceso solo desde redes de administración aprobadas y aplicar controles fuertes."],signing:["La firma SMB no se exige en uno o más hosts SMB.","Exigir firma SMB tras validar la compatibilidad."],gateway:["La puerta de enlace predeterminada expone servicios de gestión o infraestructura a la red cliente local.","Confirmar necesidad, limitar acceso de gestión y documentar responsable y firmware."],isolation:["{count} activos cliente respondieron a un único paquete ICMP desde la red par.","Revisar aislamiento de clientes, ACL de VLAN y reglas de firewall."],
  },
  "pt-BR": {
    web:["O serviço web {port} de um ativo cliente está acessível da posição de rede atual.","Confirmar a finalidade de negócio e limitar ou remover exposição desnecessária."],smb:["O serviço SMB está acessível da rede cliente par.","Fechar exposição SMB desnecessária; se necessária, segmentar a rede e exigir assinatura SMB."],remote:["O serviço de administração remota {port} está acessível.","Permitir acesso somente de redes de administração aprovadas e aplicar controles fortes."],signing:["A assinatura SMB não é exigida em um ou mais hosts SMB.","Exigir assinatura SMB após validar a compatibilidade."],gateway:["O gateway padrão expõe serviços de gestão ou infraestrutura à rede cliente local.","Confirmar necessidade, limitar acesso de gestão e documentar responsável e firmware."],isolation:["{count} ativos clientes responderam a um único pacote ICMP da rede par.","Revisar isolamento de clientes, ACLs de VLAN e regras de firewall."],
  },
  it: {
    web:["Il servizio web {port} di una risorsa client è raggiungibile dalla posizione di rete corrente.","Confermare lo scopo aziendale e limitare o rimuovere l’esposizione non necessaria."],smb:["Il servizio SMB è raggiungibile dalla rete client peer.","Chiudere l’esposizione SMB non necessaria; se richiesta, segmentare la rete e imporre la firma SMB."],remote:["Il servizio di amministrazione remota {port} è raggiungibile.","Consentire l’accesso solo dalle reti di gestione approvate e applicare controlli forti."],signing:["La firma SMB non è imposta su uno o più host SMB.","Imporre la firma SMB dopo la verifica di compatibilità."],gateway:["Il gateway predefinito espone servizi di gestione o infrastruttura alla rete client locale.","Confermare la necessità, limitare l’accesso e documentare responsabile e firmware."],isolation:["{count} risorse client hanno risposto a un singolo pacchetto ICMP dalla rete peer.","Verificare isolamento client, ACL VLAN e regole firewall."],
  },
  nl: {
    web:["De webdienst {port} van een clientasset is bereikbaar vanaf de huidige netwerkpositie.","Bevestig het zakelijke doel en beperk of verwijder onnodige blootstelling."],smb:["De SMB-dienst is bereikbaar vanuit het peer-clientnetwerk.","Sluit onnodige SMB-blootstelling; segmenteer indien nodig het netwerk en dwing SMB-ondertekening af."],remote:["De externe beheerdienst {port} is bereikbaar.","Sta alleen goedgekeurde beheernetwerken toe en pas sterke toegangscontrole toe."],signing:["SMB-ondertekening wordt op een of meer SMB-hosts niet afgedwongen.","Dwing SMB-ondertekening af na compatibiliteitsvalidatie."],gateway:["De standaardgateway stelt beheer- of infrastructuurdiensten bloot aan het lokale clientnetwerk.","Bevestig noodzaak, beperk beheertoegang en documenteer eigenaar en firmwarestatus."],isolation:["{count} clientassets reageerden op één ICMP-pakket vanuit het peernetwerk.","Controleer clientisolatie, VLAN-ACL’s en firewallregels."],
  },
};

function ruleKey(finding: string): { key: string; port?: string; count?: string } | null {
  const lower = finding.toLowerCase();
  const port = finding.match(/tcp\/\d+/i)?.[0];
  const count = finding.match(/\d+/)?.[0];
  if (lower.includes("web service") && port) return { key: "web", port };
  if (lower.includes("smb service is reachable")) return { key: "smb" };
  if (lower.includes("remote administration") && port) return { key: "remote", port };
  if (lower.includes("smb signing is not enforced")) return { key: "signing" };
  if (lower.includes("gateway exposes management") || lower.includes("gateway exposes infrastructure")) return { key: "gateway" };
  if (lower.includes("client asset") && lower.includes("icmp") && count) return { key: "isolation", count };
  return null;
}

function fill(template: string, values: { port?: string; count?: string }): string {
  return template.replace("{port}", values.port ?? "").replace("{count}", values.count ?? "");
}

const categoryNames: Record<Locale, Record<string, string>> = {
  en: { web:"Client web service exposure",smb:"Endpoint service exposure",remote:"Remote administration exposure",signing:"SMB protocol posture",gateway:"Gateway service posture",isolation:"Client isolation" },
  "zh-CN": { web:"客户端 Web 服务暴露",smb:"终端服务暴露",remote:"远程管理暴露",signing:"SMB 协议状态",gateway:"网关服务状态",isolation:"客户端隔离" },
  "zh-TW": { web:"用戶端 Web 服務暴露",smb:"終端服務暴露",remote:"遠端管理暴露",signing:"SMB 協定狀態",gateway:"閘道服務狀態",isolation:"用戶端隔離" },
  ja: { web:"クライアント Web サービス公開",smb:"エンドポイントサービス公開",remote:"リモート管理公開",signing:"SMB プロトコル状態",gateway:"ゲートウェイサービス状態",isolation:"クライアント分離" },
  ko: { web:"클라이언트 웹 서비스 노출",smb:"엔드포인트 서비스 노출",remote:"원격 관리 노출",signing:"SMB 프로토콜 상태",gateway:"게이트웨이 서비스 상태",isolation:"클라이언트 격리" },
  de: { web:"Client-Webdienst-Exposition",smb:"Endpoint-Dienst-Exposition",remote:"Remote-Administration-Exposition",signing:"SMB-Protokollstatus",gateway:"Gateway-Dienststatus",isolation:"Client-Isolierung" },
  fr: { web:"Exposition du service Web client",smb:"Exposition du service de terminal",remote:"Exposition de l’administration distante",signing:"État du protocole SMB",gateway:"État des services de passerelle",isolation:"Isolation des clients" },
  es: { web:"Exposición del servicio web cliente",smb:"Exposición del servicio de endpoint",remote:"Exposición de administración remota",signing:"Estado del protocolo SMB",gateway:"Estado de servicios de puerta de enlace",isolation:"Aislamiento de clientes" },
  "pt-BR": { web:"Exposição de serviço web cliente",smb:"Exposição de serviço de endpoint",remote:"Exposição de administração remota",signing:"Postura do protocolo SMB",gateway:"Postura de serviços do gateway",isolation:"Isolamento de clientes" },
  it: { web:"Esposizione del servizio web client",smb:"Esposizione del servizio endpoint",remote:"Esposizione dell’amministrazione remota",signing:"Stato del protocollo SMB",gateway:"Stato dei servizi gateway",isolation:"Isolamento client" },
  nl: { web:"Blootstelling client-webdienst",smb:"Blootstelling endpointdienst",remote:"Blootstelling extern beheer",signing:"SMB-protocolstatus",gateway:"Gatewaydienststatus",isolation:"Clientisolatie" },
};

export function localizeFinding(finding: ReportFinding, locale: Locale): LocalizedFinding {
  const rule = ruleKey(finding.finding);
  const localeRules = localizedRules[locale];
  const translated = rule && (localeRules[rule.key] || localizedRules.en[rule.key]);
  if (!rule || !translated) {
    return {
      ...finding,
      localizedCategory: copies[locale].otherCategory,
      localizedFinding: copies[locale].unmatchedFinding,
      localizedRecommendedAction: copies[locale].unmatchedFinding,
      localizedStatus: finding.status.toLowerCase() === "closed" ? copies[locale].closedStatus : copies[locale].openStatus,
      matched: false,
    };
  }
  return {
    ...finding,
    localizedCategory: categoryNames[locale][rule.key],
    localizedFinding: fill(translated[0], rule),
    localizedRecommendedAction: fill(translated[1], rule),
    localizedStatus: finding.status.toLowerCase() === "closed" ? copies[locale].closedStatus : copies[locale].openStatus,
    matched: true,
  };
}

export function localizeGatewayStatus(status: string | null, locale: Locale): string | null {
  if (!status) return null;
  return status === "Services observed" ? copies[locale].servicesObserved : status === "No open services observed" ? copies[locale].noServicesObserved : status;
}

const assetLabels: Record<Locale, Record<string, string>> = {
  en:{"SMB hosts":"SMB hosts","Default gateway":"Default gateway","Client network":"Client network"},
  "zh-CN":{"SMB hosts":"SMB 主机","Default gateway":"默认网关","Client network":"客户端网络"},
  "zh-TW":{"SMB hosts":"SMB 主機","Default gateway":"預設閘道","Client network":"用戶端網路"},
  ja:{"SMB hosts":"SMB ホスト","Default gateway":"デフォルトゲートウェイ","Client network":"クライアントネットワーク"},
  ko:{"SMB hosts":"SMB 호스트","Default gateway":"기본 게이트웨이","Client network":"클라이언트 네트워크"},
  de:{"SMB hosts":"SMB-Hosts","Default gateway":"Standard-Gateway","Client network":"Client-Netzwerk"},
  fr:{"SMB hosts":"Hôtes SMB","Default gateway":"Passerelle par défaut","Client network":"Réseau client"},
  es:{"SMB hosts":"Hosts SMB","Default gateway":"Puerta de enlace predeterminada","Client network":"Red cliente"},
  "pt-BR":{"SMB hosts":"Hosts SMB","Default gateway":"Gateway padrão","Client network":"Rede cliente"},
  it:{"SMB hosts":"Host SMB","Default gateway":"Gateway predefinito","Client network":"Rete client"},
  nl:{"SMB hosts":"SMB-hosts","Default gateway":"Standaardgateway","Client network":"Clientnetwerk"},
};
export const localizeAssetLabel = (asset: string, locale: Locale): string => assetLabels[locale][asset] ?? asset;
