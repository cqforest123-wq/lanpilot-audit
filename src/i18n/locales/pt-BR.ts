import type { Messages } from "../types";

export const ptBR: Messages = {
  appName: "LANPilot Audit", navRun: "Executar auditoria", navReport: "Relatório", navExport: "Exportar", navSettings: "Configurações",
  landingEyebrow: "Auditoria autorizada de governança de rede", landingTitle: "Um fluxo autorizado para evidências, achados, relatório e exportação.",
  landingDescription: "O LANPilot executa oito verificações locais aprovadas em uma ordem fixa e para imediatamente em caso de falha.",
  startAudit: "Iniciar auditoria autorizada", latestReport: "Ver relatório mais recente", authorization: "Autorização",
  authorizationDescription: "Documente o projeto autorizado e confirme todos os limites de segurança.", projectName: "Nome do projeto",
  site: "Local / organização", notes: "Observações", confirmAuthorization: "Confirmar autorização", cancel: "Cancelar",
  engineSetup: "Configuração do mecanismo", installEngine: "Instalar mecanismo incluído", updateEngine: "Atualizar mecanismo incluído",
  continueInterface: "Continuar para a interface", interface: "Interface", continueRun: "Continuar para a execução",
  runAudit: "Executar auditoria", runFullAudit: "Executar auditoria completa", stopOnFailure: "Parar em caso de falha", viewReport: "Ver relatório",
  report: "Relatório", export: "Exportar", exportZip: "Exportar ZIP", openExportFolder: "Abrir pasta de exportação",
  settings: "Configurações e sobre", language: "Idioma", unknown: "Desconhecido", missingFiles: "Arquivos de relatório ausentes",
  limitedMode: "Modo limitado", nmapUnavailable: "O nmap não está disponível. As verificações dependentes serão ignoradas.",
  safetyBoundary: "Limite de segurança", privacy: "Local primeiro, sem envio à nuvem",
  pointInTime: "Os achados são observações pontuais baseadas no cache ARP atual, acessibilidade ICMP e verificações moderadas de serviços comuns.",
  high: "Alto", medium: "Médio", low: "Baixo", reachableClients: "Clientes acessíveis", unreachableClients: "Clientes inacessíveis",
  openServiceHosts: "Hosts com serviços abertos", gatewayPosture: "Estado do gateway", riskRegister: "Registro de riscos",
  remediationRoadmap: "Roteiro de correção", executiveSummary: "Resumo executivo", technicalReport: "Relatório técnico",
  pending: "pendente", running: "executando", success: "sucesso", failed: "falha", skipped: "ignorado",
};
