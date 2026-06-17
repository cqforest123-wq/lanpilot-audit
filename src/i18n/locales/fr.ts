import type { Messages } from "../types";

export const fr: Messages = {
  appName: "LANPilot Audit", navRun: "Lancer l’audit", navReport: "Rapport", navExport: "Exporter", navSettings: "Réglages",
  landingEyebrow: "Audit autorisé de gouvernance réseau", landingTitle: "Un flux autorisé pour les preuves, constats, rapports et exports.",
  landingDescription: "LANPilot exécute huit contrôles locaux approuvés dans un ordre fixe et s’arrête immédiatement en cas d’échec.",
  startAudit: "Démarrer l’audit autorisé", latestReport: "Voir le dernier rapport", authorization: "Autorisation",
  authorizationDescription: "Documentez le projet autorisé et confirmez toutes les limites de sécurité.", projectName: "Nom du projet",
  site: "Site / organisation", notes: "Notes", confirmAuthorization: "Confirmer l’autorisation", cancel: "Annuler",
  engineSetup: "Configuration du moteur", installEngine: "Installer le moteur intégré", updateEngine: "Mettre à jour le moteur intégré",
  continueInterface: "Continuer vers l’interface", interface: "Interface", continueRun: "Continuer vers l’exécution",
  runAudit: "Lancer l’audit", runFullAudit: "Lancer l’audit complet", stopOnFailure: "Arrêt en cas d’échec", viewReport: "Voir le rapport",
  report: "Rapport", export: "Exporter", exportZip: "Exporter le ZIP", openExportFolder: "Ouvrir le dossier d’export",
  settings: "Réglages et informations", language: "Langue", unknown: "Inconnu", missingFiles: "Fichiers de rapport manquants",
  limitedMode: "Mode limité", nmapUnavailable: "nmap n’est pas disponible. Les contrôles dépendants seront ignorés.",
  safetyBoundary: "Limite de sécurité", privacy: "Local d’abord, aucun envoi cloud",
  pointInTime: "Les constats sont des observations ponctuelles basées sur le cache ARP actuel, l’accessibilité ICMP et des contrôles modérés des services courants.",
  high: "Élevé", medium: "Moyen", low: "Faible", reachableClients: "Clients accessibles", unreachableClients: "Clients inaccessibles",
  openServiceHosts: "Hôtes avec services ouverts", gatewayPosture: "État de la passerelle", riskRegister: "Registre des risques",
  remediationRoadmap: "Feuille de route de remédiation", executiveSummary: "Résumé exécutif", technicalReport: "Rapport technique",
  pending: "en attente", running: "en cours", success: "réussi", failed: "échec", skipped: "ignoré",
};
