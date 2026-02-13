# Baseline Systems for Academic Comparison

Bu klasör, akademik makale için karşılaştırmalı analiz yapmak üzere baseline sistemleri içerir.

## Baseline Sistemleri

### 1. OIDC Federation (Keycloak)
- **Klasör:** `oidc-baseline/`
- **Port:** 3100 (client), 8080 (Keycloak)
- **Açıklama:** Geleneksel OpenID Connect federasyonu
- **Karşılaştırma amacı:** Traditional federation vs our solution

### 2. Centralized Identity System
- **Klasör:** `centralized-baseline/`
- **Port:** 3200
- **Açıklama:** PostgreSQL + Redis ile merkezi kimlik yönetimi
- **Karşılaştırma amacı:** Centralized vs decentralized approach

### 3. Indy Simulator
- **Klasör:** `indy-baseline/`
- **Port:** 3300
- **Açıklama:** Hyperledger Indy operasyonlarını simüle eder
- **Karşılaştırma amacı:** Indy-based SSI vs our hybrid approach

## Kullanım

### Tüm Baseline'ları Başlat

```bash
cd baselines
docker-compose -f docker-compose.baselines.yml up -d
```

### Benchmark Çalıştır

```bash
# Hızlı test (30 run)
docker-compose -f docker-compose.baselines.yml run benchmark-runner node runner.js --quick

# Tam test (100 run)
docker-compose -f docker-compose.baselines.yml run benchmark-runner node runner.js --full
```

### Manuel Test

```bash
# OIDC Baseline
curl http://localhost:3100/health

# Centralized Baseline
curl http://localhost:3200/health

# Indy Baseline
curl http://localhost:3300/health
```

## Metrikler

Her baseline aşağıdaki metrikleri sağlar:

| Metrik | Endpoint | Açıklama |
|--------|----------|----------|
| Health | `/health` | Sistem durumu |
| Metrics | `/metrics` | Performans metrikleri |
| Reset | `POST /metrics/reset` | Metrikleri sıfırla |

## Benchmark Sonuçları

Sonuçlar `benchmark/results/` klasöründe saklanır:

- `benchmark-{timestamp}.json` - Raw JSON data
- `report-{timestamp}.md` - Markdown rapor
- `latency-{timestamp}.csv` - CSV analiz için

## İstatistiksel Analiz

Benchmark runner otomatik olarak şunları hesaplar:

- **Descriptive Statistics:** Mean, median, P50, P95, P99, std dev
- **Confidence Intervals:** 95% CI
- **Hypothesis Testing:** Two-sample t-test
- **Effect Size:** Cohen's d

## Test Senaryoları

### 1. Credential Issuance
Her sistemde credential oluşturma latency'si

### 2. Cross-Domain Verification
Farklı domain'ler arası doğrulama süresi

### 3. Full Flow
Uçtan uca akış: issuance → verification

### 4. Throughput
Farklı concurrency level'larında (1, 5, 10, 20, 50, 100) throughput

## Akademik Kullanım

Bu baseline'lar aşağıdaki karşılaştırmaları destekler:

| Karşılaştırma | Metrik | Beklenen Sonuç |
|---------------|--------|----------------|
| OIDC vs Ours | Latency | Our solution ~2x slower (blockchain overhead) |
| Centralized vs Ours | Latency | Our solution ~3x slower |
| Indy vs Ours | Latency | Comparable or better |
| All vs Ours | Trust Model | Our solution: decentralized + policy-based |
| All vs Ours | Privacy | Our solution: selective disclosure |

## Notlar

- Indy baseline simülasyondur, gerçek Indy ledger kullanmaz
- OIDC baseline Keycloak kullanır
- Tüm latency değerleri milisaniye cinsindendir
- İstatistiksel anlamlılık için minimum 30 run gereklidir
