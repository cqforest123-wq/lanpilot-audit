import type { Locale } from "./i18n/types";
import { deduplicateFindings, localizeAssetLabel, localizeFinding, type ReportFinding } from "./report-localization";

export type RemediationStatus = "open" | "assigned" | "in_progress" | "remediated" | "accepted_risk" | "retest_required" | "verified";

export interface RemediationTicket {
  id: string; findingFingerprint: string; severity: string; asset: string; category: string;
  localizedFinding: string; localizedRecommendedAction: string; owner: string; dueDate: string;
  priority: string; status: RemediationStatus; businessJustification: string; manualSteps: string[];
  validationSteps: string[]; rollbackConsiderations: string[]; evidenceReferences: string[]; notes: string;
}
export interface RemediationPack {
  id: string; generatedAt: string; labDirectory: string; language: Locale;
  riskSummary: Record<string, number>; findings: ReportFinding[]; tickets: RemediationTicket[];
  verificationPlan: string[]; acceptanceRecords: unknown[];
}

const copy: Record<Locale, { manual: string[]; validate: string[]; rollback: string[]; generic: string[] }> = {
  en:{manual:["Confirm the business purpose and assign an authorized administrator.","Apply the least-access principle during an approved maintenance window.","Record the owner, exception, and outcome."],validate:["Run an authorized LANPilot retest and compare the latest snapshot.","Confirm exposure is removed or limited to approved networks."],rollback:["Document compatibility impact and an approved rollback plan before manual changes."],generic:["Review the observation with the responsible administrator.","Document a manual remediation decision and verification result."]},
  "zh-CN":{manual:["确认业务用途并分派授权管理员。","在批准的维护窗口内按最小访问原则人工整改。","记录负责人、例外和结果。"],validate:["执行授权复测并对比最新快照。","确认暴露已移除或仅限授权网段。"],rollback:["人工变更前记录兼容性影响和经批准的回退方案。"],generic:["由责任管理员复核该观察结果。","记录人工整改决策和验证结果。"]},
  "zh-TW":{manual:["確認業務用途並分派授權管理員。","在核准的維護時段內依最小存取原則人工修正。","記錄負責人、例外及結果。"],validate:["執行授權複測並比較最新快照。","確認暴露已移除或僅限核准網段。"],rollback:["人工變更前記錄相容性影響及核准的回復方案。"],generic:["由負責管理員複核此觀察結果。","記錄人工修正決策及驗證結果。"]},
  ja:{manual:["業務目的を確認し、承認済み管理者を割り当てます。","承認済み保守時間に最小アクセス原則で手動是正します。","担当者、例外、結果を記録します。"],validate:["承認済み再テストを実行し、最新スナップショットを比較します。","公開が削除されたか承認済みネットワークに限定されたことを確認します。"],rollback:["手動変更前に互換性への影響と承認済みロールバック計画を記録します。"],generic:["担当管理者と観測結果を確認します。","手動是正の判断と検証結果を記録します。"]},
  ko:{manual:["업무 목적을 확인하고 승인된 관리자를 지정합니다.","승인된 유지보수 시간에 최소 접근 원칙으로 수동 개선합니다.","담당자, 예외 및 결과를 기록합니다."],validate:["승인된 재검사를 실행하고 최신 스냅샷을 비교합니다.","노출이 제거되었거나 승인된 네트워크로 제한되었는지 확인합니다."],rollback:["수동 변경 전에 호환성 영향과 승인된 롤백 계획을 기록합니다."],generic:["담당 관리자와 관찰 결과를 검토합니다.","수동 개선 결정과 검증 결과를 기록합니다."]},
  de:{manual:["Geschäftszweck bestätigen und autorisierte Administration zuweisen.","Manuelle Behebung im genehmigten Wartungsfenster nach dem Prinzip minimaler Zugriffe durchführen.","Verantwortliche, Ausnahmen und Ergebnis dokumentieren."],validate:["Autorisierten LANPilot-Nachtest ausführen und Snapshot vergleichen.","Bestätigen, dass die Exposition entfernt oder eingeschränkt wurde."],rollback:["Kompatibilitätsauswirkungen und genehmigten Rücksetzplan dokumentieren."],generic:["Beobachtung mit Verantwortlichen prüfen.","Manuelle Entscheidung und Prüfung dokumentieren."]},
  fr:{manual:["Confirmer l’usage métier et désigner un administrateur autorisé.","Corriger manuellement selon le moindre accès pendant une fenêtre approuvée.","Documenter responsable, exception et résultat."],validate:["Exécuter un nouveau test autorisé et comparer l’instantané.","Confirmer que l’exposition est supprimée ou limitée."],rollback:["Documenter l’impact de compatibilité et le plan de retour approuvé."],generic:["Examiner l’observation avec le responsable.","Documenter la décision manuelle et la vérification."]},
  es:{manual:["Confirmar el uso empresarial y asignar un administrador autorizado.","Corregir manualmente con acceso mínimo durante una ventana aprobada.","Registrar responsable, excepción y resultado."],validate:["Ejecutar una nueva prueba autorizada y comparar la instantánea.","Confirmar que la exposición se eliminó o limitó."],rollback:["Documentar impacto de compatibilidad y plan de reversión aprobado."],generic:["Revisar la observación con el responsable.","Documentar la decisión manual y la verificación."]},
  "pt-BR":{manual:["Confirmar a finalidade de negócio e designar administrador autorizado.","Corrigir manualmente com acesso mínimo em janela aprovada.","Registrar responsável, exceção e resultado."],validate:["Executar novo teste autorizado e comparar o snapshot.","Confirmar que a exposição foi removida ou limitada."],rollback:["Documentar impacto de compatibilidade e plano de reversão aprovado."],generic:["Revisar a observação com o responsável.","Documentar decisão manual e verificação."]},
  it:{manual:["Confermare lo scopo aziendale e assegnare un amministratore autorizzato.","Correggere manualmente con accesso minimo nella finestra approvata.","Registrare responsabile, eccezione e risultato."],validate:["Eseguire un nuovo test autorizzato e confrontare l’istantanea.","Confermare che l’esposizione sia rimossa o limitata."],rollback:["Documentare impatto di compatibilità e piano di ripristino approvato."],generic:["Esaminare l’osservazione con il responsabile.","Documentare decisione manuale e verifica."]},
  nl:{manual:["Bevestig het zakelijke doel en wijs een bevoegde beheerder toe.","Voer handmatig herstel uit met minimale toegang in een goedgekeurd venster.","Leg eigenaar, uitzondering en resultaat vast."],validate:["Voer een geautoriseerde hertest uit en vergelijk de momentopname.","Bevestig dat blootstelling is verwijderd of beperkt."],rollback:["Documenteer compatibiliteitsimpact en goedgekeurd terugvalplan."],generic:["Beoordeel de observatie met de eigenaar.","Documenteer handmatige beslissing en verificatie."]},
};

const fingerprint = (finding: ReportFinding) => [finding.severity,finding.asset,finding.category,finding.finding].join("|").toLowerCase().replace(/[^a-z0-9|]+/g,"-").slice(0,120);
export function buildRemediationPack(findings: ReportFinding[], locale: Locale, labDirectory: string): RemediationPack {
  const unique = deduplicateFindings(findings);
  const tickets = unique.map((finding, index): RemediationTicket => {
    const localized = localizeFinding(finding, locale);
    const guidance = copy[locale];
    return { id:`RMT-${String(index + 1).padStart(3,"0")}`, findingFingerprint:fingerprint(finding), severity:finding.severity,
      asset:localizeAssetLabel(finding.asset, locale), category:localized.localizedCategory, localizedFinding:localized.localizedFinding,
      localizedRecommendedAction:localized.localizedRecommendedAction, owner:"", dueDate:"", priority:finding.severity, status:"open",
      businessJustification:"", manualSteps:localized.matched ? guidance.manual : guidance.generic, validationSteps:guidance.validate,
      rollbackConsiderations:guidance.rollback, evidenceReferences:["04-risk/network-issues-register.csv"], notes:"" };
  });
  const riskSummary = Object.fromEntries(["High","Medium","Low"].map((severity) => [severity, unique.filter((finding) => finding.severity === severity).length]));
  return { id:`remediation-pack-${Date.now()}`, generatedAt:new Date().toISOString(), labDirectory, language:locale, riskSummary, findings:unique, tickets,
    verificationPlan:copy[locale].validate, acceptanceRecords:[] };
}
