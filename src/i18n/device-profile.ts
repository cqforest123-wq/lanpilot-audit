import type { Locale, Messages } from "./types";

export const deviceProfileMessages: Record<Locale, Messages> = {
  en: {
    "deviceProfile.title": "Evidence-linked device profiles",
    "deviceProfile.description": "Profiles combine only records captured in this audit. The score measures evidence coverage, not identity certainty.",
    "deviceProfile.ip": "IP address", "deviceProfile.mac": "MAC / OUI", "deviceProfile.vendor": "Vendor / category",
    "deviceProfile.ports": "Open services", "deviceProfile.coverage": "Evidence coverage", "deviceProfile.sources": "Evidence",
    "deviceProfile.localMac": "Locally administered MAC; it may be randomized. Vendor lookup may not apply.",
    "deviceProfile.mdns": "Bonjour services", "deviceProfile.notCollected": "Not collected", "deviceProfile.none": "None observed",
    "deviceProfile.source.audit-asset-inventory": "Asset inventory", "deviceProfile.source.arp-neighbor-cache": "ARP cache", "deviceProfile.source.single-icmp-reachability-check": "ICMP reachability",
    "deviceProfile.source.low-intensity-service-check": "Service check", "deviceProfile.source.bonjour-mdns-observation": "Bonjour / mDNS",
  },
  "zh-CN": {
    "deviceProfile.title": "基于证据的设备画像", "deviceProfile.description": "画像只合并本次审计实际采集的记录。分数表示证据覆盖度，不代表身份判断的概率。",
    "deviceProfile.ip": "IP 地址", "deviceProfile.mac": "MAC / OUI", "deviceProfile.vendor": "厂商 / 类别", "deviceProfile.ports": "开放服务", "deviceProfile.coverage": "证据覆盖度", "deviceProfile.sources": "证据来源",
    "deviceProfile.localMac": "本地管理 MAC，可能是随机地址；厂商查询可能不适用。", "deviceProfile.mdns": "Bonjour 服务", "deviceProfile.notCollected": "未采集", "deviceProfile.none": "未观察到",
    "deviceProfile.source.audit-asset-inventory": "资产清单", "deviceProfile.source.arp-neighbor-cache": "ARP 缓存", "deviceProfile.source.single-icmp-reachability-check": "ICMP 可达性", "deviceProfile.source.low-intensity-service-check": "服务检测", "deviceProfile.source.bonjour-mdns-observation": "Bonjour / mDNS",
  },
  "zh-TW": {
    "deviceProfile.title": "以證據關聯的裝置画像", "deviceProfile.description": "僅合併本次稽核實際擷取的記錄。分數代表證據涵蓋度，不代表身分判斷機率。",
    "deviceProfile.ip": "IP 位址", "deviceProfile.mac": "MAC / OUI", "deviceProfile.vendor": "廠商 / 類別", "deviceProfile.ports": "開放服務", "deviceProfile.coverage": "證據涵蓋度", "deviceProfile.sources": "證據來源",
    "deviceProfile.localMac": "本機管理 MAC，可能是隨機位址；廠商查詢可能不適用。", "deviceProfile.mdns": "Bonjour 服務", "deviceProfile.notCollected": "未擷取", "deviceProfile.none": "未觀察到",
    "deviceProfile.source.audit-asset-inventory": "資產清單", "deviceProfile.source.arp-neighbor-cache": "ARP 快取", "deviceProfile.source.single-icmp-reachability-check": "ICMP 可達性", "deviceProfile.source.low-intensity-service-check": "服務檢查", "deviceProfile.source.bonjour-mdns-observation": "Bonjour / mDNS",
  },
  ja: {
    "deviceProfile.title": "証拠に基づくデバイスプロファイル", "deviceProfile.description": "この監査で実際に収集した記録のみを統合します。スコアは証拠の網羅度であり、識別の確率ではありません。",
    "deviceProfile.ip": "IP アドレス", "deviceProfile.mac": "MAC / OUI", "deviceProfile.vendor": "ベンダー / 種別", "deviceProfile.ports": "公開サービス", "deviceProfile.coverage": "証拠の網羅度", "deviceProfile.sources": "証拠",
    "deviceProfile.localMac": "ローカル管理 MAC です。ランダム化アドレスの可能性があり、ベンダー照合は適用できない場合があります。", "deviceProfile.mdns": "Bonjour サービス", "deviceProfile.notCollected": "未収集", "deviceProfile.none": "観測なし",
    "deviceProfile.source.audit-asset-inventory": "資産インベントリ", "deviceProfile.source.arp-neighbor-cache": "ARP キャッシュ", "deviceProfile.source.single-icmp-reachability-check": "ICMP 到達性", "deviceProfile.source.low-intensity-service-check": "サービス確認", "deviceProfile.source.bonjour-mdns-observation": "Bonjour / mDNS",
  },
  ko: {
    "deviceProfile.title": "증거 기반 기기 프로필", "deviceProfile.description": "이번 감사에서 실제 수집한 기록만 결합합니다. 점수는 증거 범위이며 기기 식별 확률이 아닙니다.",
    "deviceProfile.ip": "IP 주소", "deviceProfile.mac": "MAC / OUI", "deviceProfile.vendor": "제조사 / 범주", "deviceProfile.ports": "열린 서비스", "deviceProfile.coverage": "증거 범위", "deviceProfile.sources": "증거",
    "deviceProfile.localMac": "로컬 관리 MAC입니다. 무작위 주소일 수 있으며 제조사 조회가 맞지 않을 수 있습니다.", "deviceProfile.mdns": "Bonjour 서비스", "deviceProfile.notCollected": "수집되지 않음", "deviceProfile.none": "관찰되지 않음",
    "deviceProfile.source.audit-asset-inventory": "자산 목록", "deviceProfile.source.arp-neighbor-cache": "ARP 캐시", "deviceProfile.source.single-icmp-reachability-check": "ICMP 도달성", "deviceProfile.source.low-intensity-service-check": "서비스 확인", "deviceProfile.source.bonjour-mdns-observation": "Bonjour / mDNS",
  },
  de: {
    "deviceProfile.title": "Evidenzbasierte Geräteprofile", "deviceProfile.description": "Es werden nur Datensätze aus diesem Audit zusammengeführt. Der Wert beschreibt die Evidenzabdeckung, nicht die Wahrscheinlichkeit einer Identität.",
    "deviceProfile.ip": "IP-Adresse", "deviceProfile.mac": "MAC / OUI", "deviceProfile.vendor": "Hersteller / Kategorie", "deviceProfile.ports": "Offene Dienste", "deviceProfile.coverage": "Evidenzabdeckung", "deviceProfile.sources": "Evidenz",
    "deviceProfile.localMac": "Lokal verwaltete MAC-Adresse; sie kann randomisiert sein. Eine Herstellerzuordnung ist eventuell nicht möglich.", "deviceProfile.mdns": "Bonjour-Dienste", "deviceProfile.notCollected": "Nicht erfasst", "deviceProfile.none": "Nicht beobachtet",
    "deviceProfile.source.audit-asset-inventory": "Assetinventar", "deviceProfile.source.arp-neighbor-cache": "ARP-Cache", "deviceProfile.source.single-icmp-reachability-check": "ICMP-Erreichbarkeit", "deviceProfile.source.low-intensity-service-check": "Dienstprüfung", "deviceProfile.source.bonjour-mdns-observation": "Bonjour / mDNS",
  },
  fr: {
    "deviceProfile.title": "Profils d’appareils fondés sur des preuves", "deviceProfile.description": "Seules les données recueillies pendant cet audit sont regroupées. Le score mesure la couverture des preuves, pas la probabilité d’identification.",
    "deviceProfile.ip": "Adresse IP", "deviceProfile.mac": "MAC / OUI", "deviceProfile.vendor": "Fabricant / catégorie", "deviceProfile.ports": "Services ouverts", "deviceProfile.coverage": "Couverture des preuves", "deviceProfile.sources": "Éléments",
    "deviceProfile.localMac": "Adresse MAC administrée localement, possiblement aléatoire ; l’identification du fabricant peut être indisponible.", "deviceProfile.mdns": "Services Bonjour", "deviceProfile.notCollected": "Non collecté", "deviceProfile.none": "Aucune observation",
    "deviceProfile.source.audit-asset-inventory": "Inventaire des actifs", "deviceProfile.source.arp-neighbor-cache": "Cache ARP", "deviceProfile.source.single-icmp-reachability-check": "Accessibilité ICMP", "deviceProfile.source.low-intensity-service-check": "Vérification des services", "deviceProfile.source.bonjour-mdns-observation": "Bonjour / mDNS",
  },
  es: {
    "deviceProfile.title": "Perfiles de dispositivos basados en evidencias", "deviceProfile.description": "Solo se combinan registros recopilados en esta auditoría. La puntuación mide la cobertura de evidencias, no la probabilidad de identidad.",
    "deviceProfile.ip": "Dirección IP", "deviceProfile.mac": "MAC / OUI", "deviceProfile.vendor": "Fabricante / categoría", "deviceProfile.ports": "Servicios abiertos", "deviceProfile.coverage": "Cobertura de evidencias", "deviceProfile.sources": "Evidencias",
    "deviceProfile.localMac": "MAC administrada localmente; podría ser aleatoria. La consulta del fabricante quizá no sea aplicable.", "deviceProfile.mdns": "Servicios Bonjour", "deviceProfile.notCollected": "No recopilado", "deviceProfile.none": "Sin observaciones",
    "deviceProfile.source.audit-asset-inventory": "Inventario de activos", "deviceProfile.source.arp-neighbor-cache": "Caché ARP", "deviceProfile.source.single-icmp-reachability-check": "Alcance ICMP", "deviceProfile.source.low-intensity-service-check": "Comprobación de servicios", "deviceProfile.source.bonjour-mdns-observation": "Bonjour / mDNS",
  },
  "pt-BR": {
    "deviceProfile.title": "Perfis de dispositivos vinculados a evidências", "deviceProfile.description": "Apenas registros coletados nesta auditoria são combinados. A pontuação mede a cobertura das evidências, não a probabilidade da identidade.",
    "deviceProfile.ip": "Endereço IP", "deviceProfile.mac": "MAC / OUI", "deviceProfile.vendor": "Fabricante / categoria", "deviceProfile.ports": "Serviços abertos", "deviceProfile.coverage": "Cobertura de evidências", "deviceProfile.sources": "Evidências",
    "deviceProfile.localMac": "MAC administrado localmente; pode ser aleatório. A identificação do fabricante pode não se aplicar.", "deviceProfile.mdns": "Serviços Bonjour", "deviceProfile.notCollected": "Não coletado", "deviceProfile.none": "Nenhuma observação",
    "deviceProfile.source.audit-asset-inventory": "Inventário de ativos", "deviceProfile.source.arp-neighbor-cache": "Cache ARP", "deviceProfile.source.single-icmp-reachability-check": "Alcance ICMP", "deviceProfile.source.low-intensity-service-check": "Verificação de serviços", "deviceProfile.source.bonjour-mdns-observation": "Bonjour / mDNS",
  },
  it: {
    "deviceProfile.title": "Profili dei dispositivi basati su evidenze", "deviceProfile.description": "Vengono uniti solo i dati raccolti in questo audit. Il punteggio misura la copertura delle evidenze, non la probabilità dell’identità.",
    "deviceProfile.ip": "Indirizzo IP", "deviceProfile.mac": "MAC / OUI", "deviceProfile.vendor": "Produttore / categoria", "deviceProfile.ports": "Servizi aperti", "deviceProfile.coverage": "Copertura delle evidenze", "deviceProfile.sources": "Evidenze",
    "deviceProfile.localMac": "MAC amministrato localmente, potenzialmente casuale; il riconoscimento del produttore potrebbe non essere applicabile.", "deviceProfile.mdns": "Servizi Bonjour", "deviceProfile.notCollected": "Non raccolto", "deviceProfile.none": "Nessuna osservazione",
    "deviceProfile.source.audit-asset-inventory": "Inventario risorse", "deviceProfile.source.arp-neighbor-cache": "Cache ARP", "deviceProfile.source.single-icmp-reachability-check": "Raggiungibilità ICMP", "deviceProfile.source.low-intensity-service-check": "Controllo servizi", "deviceProfile.source.bonjour-mdns-observation": "Bonjour / mDNS",
  },
  nl: {
    "deviceProfile.title": "Apparaatprofielen op basis van bewijs", "deviceProfile.description": "Alleen gegevens uit deze audit worden gecombineerd. De score meet de dekking van bewijs, niet de kans op een juiste identiteit.",
    "deviceProfile.ip": "IP-adres", "deviceProfile.mac": "MAC / OUI", "deviceProfile.vendor": "Fabrikant / categorie", "deviceProfile.ports": "Open services", "deviceProfile.coverage": "Bewijsdekking", "deviceProfile.sources": "Bewijs",
    "deviceProfile.localMac": "Lokaal beheerd MAC-adres; mogelijk gerandomiseerd. Fabrikantidentificatie is mogelijk niet van toepassing.", "deviceProfile.mdns": "Bonjour-services", "deviceProfile.notCollected": "Niet verzameld", "deviceProfile.none": "Niet waargenomen",
    "deviceProfile.source.audit-asset-inventory": "Assetinventaris", "deviceProfile.source.arp-neighbor-cache": "ARP-cache", "deviceProfile.source.single-icmp-reachability-check": "ICMP-bereikbaarheid", "deviceProfile.source.low-intensity-service-check": "Servicecontrole", "deviceProfile.source.bonjour-mdns-observation": "Bonjour / mDNS",
  },
};
