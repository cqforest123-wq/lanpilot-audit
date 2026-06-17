import type { Messages } from "../types";

export const ko: Messages = {
  appName: "LANPilot Audit", navRun: "감사 실행", navReport: "보고서", navExport: "내보내기", navSettings: "설정",
  landingEyebrow: "승인된 네트워크 거버넌스 감사", landingTitle: "승인된 하나의 흐름으로 증거, 발견 사항, 보고서 및 내보내기를 완료합니다.",
  landingDescription: "LANPilot은 승인된 13개의 로컬 검사를 고정된 순서로 실행하고 실패 시 즉시 중지합니다.",
  startAudit: "승인 감사 시작", latestReport: "최신 보고서 보기", authorization: "승인 확인",
  authorizationDescription: "승인된 프로젝트를 기록하고 모든 안전 경계를 확인하세요.", projectName: "프로젝트 이름",
  site: "사이트 / 조직", notes: "메모", confirmAuthorization: "승인 확인", cancel: "취소",
  engineSetup: "엔진 설정", installEngine: "내장 엔진 설치", updateEngine: "내장 엔진 업데이트",
  continueInterface: "인터페이스 확인으로 계속", interface: "인터페이스", continueRun: "실행으로 계속",
  runAudit: "감사 실행", runFullAudit: "전체 감사 실행", stopOnFailure: "실패 시 중지", viewReport: "보고서 보기",
  report: "보고서", export: "내보내기", exportZip: "ZIP 내보내기", openExportFolder: "내보내기 폴더 열기",
  settings: "설정 및 정보", language: "언어", unknown: "알 수 없음", missingFiles: "누락된 보고서 파일",
  limitedMode: "제한 모드", nmapUnavailable: "nmap을 사용할 수 없습니다. 관련 검사는 건너뜁니다.",
  safetyBoundary: "안전 경계", privacy: "로컬 우선, 클라우드 업로드 없음",
  pointInTime: "발견 사항은 현재 ARP 캐시, ICMP 도달 가능성 및 저강도 일반 서비스 검사를 기반으로 한 시점 관찰입니다.",
  high: "높음", medium: "중간", low: "낮음", reachableClients: "도달 가능한 클라이언트", unreachableClients: "도달 불가능한 클라이언트",
  openServiceHosts: "열린 서비스 호스트", gatewayPosture: "게이트웨이 상태", riskRegister: "위험 대장",
  remediationRoadmap: "개선 로드맵", executiveSummary: "요약 보고서", technicalReport: "기술 보고서",
  pending: "대기", running: "실행 중", success: "성공", failed: "실패", skipped: "건너뜀",
};
