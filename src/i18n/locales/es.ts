import type { Messages } from "../types";

export const es: Messages = {
  appName: "LANPilot Audit", navRun: "Ejecutar auditoría", navReport: "Informe", navExport: "Exportar", navSettings: "Ajustes",
  landingEyebrow: "Auditoría autorizada de gobierno de red", landingTitle: "Un flujo autorizado para evidencias, hallazgos, informes y exportación.",
  landingDescription: "LANPilot ejecuta ocho comprobaciones locales aprobadas en un orden fijo y se detiene inmediatamente si alguna falla.",
  startAudit: "Iniciar auditoría autorizada", latestReport: "Ver informe más reciente", authorization: "Autorización",
  authorizationDescription: "Documente el proyecto autorizado y confirme todos los límites de seguridad.", projectName: "Nombre del proyecto",
  site: "Sitio / organización", notes: "Notas", confirmAuthorization: "Confirmar autorización", cancel: "Cancelar",
  engineSetup: "Configuración del motor", installEngine: "Instalar motor incluido", updateEngine: "Actualizar motor incluido",
  continueInterface: "Continuar a la interfaz", interface: "Interfaz", continueRun: "Continuar a la ejecución",
  runAudit: "Ejecutar auditoría", runFullAudit: "Ejecutar auditoría completa", stopOnFailure: "Detener al fallar", viewReport: "Ver informe",
  report: "Informe", export: "Exportar", exportZip: "Exportar ZIP", openExportFolder: "Abrir carpeta de exportación",
  settings: "Ajustes e información", language: "Idioma", unknown: "Desconocido", missingFiles: "Archivos de informe ausentes",
  limitedMode: "Modo limitado", nmapUnavailable: "nmap no está disponible. Se omitirán las comprobaciones dependientes.",
  safetyBoundary: "Límite de seguridad", privacy: "Local primero, sin carga a la nube",
  pointInTime: "Los hallazgos son observaciones puntuales basadas en la caché ARP actual, la accesibilidad ICMP y comprobaciones moderadas de servicios comunes.",
  high: "Alto", medium: "Medio", low: "Bajo", reachableClients: "Clientes accesibles", unreachableClients: "Clientes inaccesibles",
  openServiceHosts: "Hosts con servicios abiertos", gatewayPosture: "Estado de la puerta de enlace", riskRegister: "Registro de riesgos",
  remediationRoadmap: "Hoja de ruta de corrección", executiveSummary: "Resumen ejecutivo", technicalReport: "Informe técnico",
  pending: "pendiente", running: "en curso", success: "correcto", failed: "fallido", skipped: "omitido",
};
