import type { Messages } from "../types";

export const it: Messages = {
  appName: "LANPilot Audit", navRun: "Esegui audit", navReport: "Rapporto", navExport: "Esporta", navSettings: "Impostazioni",
  landingEyebrow: "Audit autorizzato di governance della rete", landingTitle: "Un flusso autorizzato per evidenze, risultati, rapporto ed esportazione.",
  landingDescription: "LANPilot esegue otto controlli locali approvati in un ordine fisso e si arresta immediatamente in caso di errore.",
  startAudit: "Avvia audit autorizzato", latestReport: "Visualizza il rapporto più recente", authorization: "Autorizzazione",
  authorizationDescription: "Documenta il progetto autorizzato e conferma tutti i limiti di sicurezza.", projectName: "Nome progetto",
  site: "Sito / organizzazione", notes: "Note", confirmAuthorization: "Conferma autorizzazione", cancel: "Annulla",
  engineSetup: "Configurazione motore", installEngine: "Installa motore incluso", updateEngine: "Aggiorna motore incluso",
  continueInterface: "Continua all’interfaccia", interface: "Interfaccia", continueRun: "Continua all’esecuzione",
  runAudit: "Esegui audit", runFullAudit: "Esegui audit completo", stopOnFailure: "Interrompi in caso di errore", viewReport: "Visualizza rapporto",
  report: "Rapporto", export: "Esporta", exportZip: "Esporta ZIP", openExportFolder: "Apri cartella di esportazione",
  settings: "Impostazioni e informazioni", language: "Lingua", unknown: "Sconosciuto", missingFiles: "File del rapporto mancanti",
  limitedMode: "Modalità limitata", nmapUnavailable: "nmap non è disponibile. I controlli dipendenti verranno saltati.",
  safetyBoundary: "Limite di sicurezza", privacy: "Locale per impostazione, nessun upload cloud",
  pointInTime: "I risultati sono osservazioni puntuali basate sulla cache ARP corrente, sulla raggiungibilità ICMP e su controlli moderati dei servizi comuni.",
  high: "Alto", medium: "Medio", low: "Basso", reachableClients: "Client raggiungibili", unreachableClients: "Client non raggiungibili",
  openServiceHosts: "Host con servizi aperti", gatewayPosture: "Stato del gateway", riskRegister: "Registro dei rischi",
  remediationRoadmap: "Piano di correzione", executiveSummary: "Riepilogo esecutivo", technicalReport: "Rapporto tecnico",
  pending: "in attesa", running: "in corso", success: "riuscito", failed: "non riuscito", skipped: "saltato",
};
