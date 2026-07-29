# P5 Validasyon Raporu

Tarih: 2026-07-29
Dal: `feature/p5.10-finalization`

## Kapsam sonucu

| Faz | Kapsam | Sonuç |
|---|---|---|
| P5.1 | Vault KV versioning, doğrulama, rollback | Geçti |
| P5.2 | Atomik file-system export, izin, backup, rollback | Geçti |
| P5.3 | Kubernetes TLS Secret, conflict, metadata, rollback | Geçti |
| P5.4 | Bağımsız IIS agent, registration, pull job, binding/CCS, rollback | Geçti |
| P5.5 | NGNIX ve Apache SSH deployer | Geçti |
| P5.6 | AWS ACM import/update/rollback | Geçti |
| P5.7 | Azure Key Vault versioned import/rollback | Geçti |
| P5.8 | Azure Application Gateway reference/upload/rollback | Geçti |
| P5.9 | External TLS ve multi-node quorum doğrulaması | Geçti |
| P5.10 | Deployment metrikleri ve deployer sözleşme validasyonu | Geçti |

## P5.10 çıktıları

- Düşük cardinality label kullanan success/failure, retry, rollback, verification ve süre metrikleri eklendi.
- Planlanan on deployer'ın DI kayıt sözleşmesi otomatik testle güvenceye alındı.
- `/metrics` endpoint'i entegrasyon testiyle doğrulandı.
- Metriklerde target adı, domain, endpoint, fingerprint ve sertifika materyali kullanılmadığı test edildi.

## Otomatik validasyon

Bu bölüm son doğrulama çalıştırmasının sonuçlarıyla güncellenmiştir:

| Kontrol | Sonuç |
|---|---|
| Ana .NET unit/integration testleri | Geçti — 169 unit, 4 integration |
| `winDeployAgent` testleri | Geçti — 9 test |
| Python worker testleri | Geçti — 3 test |
| EF Core pending model change | Geçti — model migration snapshot ile uyumlu |
| Temiz SQLite migration uygulaması | Geçti — tüm migration'lar boş DB'ye uygulandı |
| Docker Compose build ve health | Geçti — üç uygulama imajı build edildi; web ve iki worker healthy |
| Canlı readiness ve metrics | Geçti — `/health/ready` 200, deployment HELP serileri mevcut |
| `git diff --check` | Geçti |

## Güvenlik ve veri sahipliği

- Private key'i yönetilen sertifikalarda sertifika bundle'ının source of truth'ı Vault'tur.
- Yenileme yeni Vault version üretir; DB yalnızca durum, fingerprint, Vault path/version referansı ve operasyonel metadata tutar.
- Deployment bundle'ı DB sertifika içeriğinden değil Vault'tan okunur.
- Asset/discovery ile edinilen public sertifikalar bu kuralın dışındadır ve envanter amacıyla DB'de tutulabilir.
- UI, log ve Prometheus label'larında private key/PFX/token yayınlanmaması testlerle korunur.

## Ortama bağlı kontroller

Gerçek AWS, Azure, Kubernetes, SSH sunucusu ve Windows IIS smoke testleri geçerli abonelik/cluster/makine credential'ı gerektirir. Repository içindeki gateway/fake-client, contract, Windows IIS fixture ve orchestration testleri davranışı doğrular; üretime geçişte her hedef için staging hesabında gerçek smoke test ayrıca uygulanmalıdır.

## Genel değerlendirme

P5 fonksiyonel kapsamı tamamlanmıştır. Üretim kabulü için ortama bağlı smoke testler, credential politikaları, ağ erişimi ve hedefe özel rollback tatbikatı işletim ekibinin release kapısı olarak tutulmalıdır.
