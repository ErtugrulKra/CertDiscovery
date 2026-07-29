# CertDiscovery Kullanıcı Rehberi

Bu rehber CertDiscovery'yi kuran, yöneten ve günlük sertifika operasyonlarında kullanan ekipler içindir. Ekran adları uygulamadaki İngilizce adlarıyla verilmiştir.

## 1. Hızlı başlangıç

Gereksinim: Docker Desktop ve çalışan Docker daemon.

```powershell
git clone https://github.com/ErtugrulKra/CertDiscovery.git
cd CertDiscovery
docker compose up --build -d
docker compose ps
```

Web arayüzü `http://localhost:8080`, Swagger `http://localhost:8080/swagger`, Prometheus metrikleri `http://localhost:8080/metrics`, geliştirme Vault'u `http://localhost:8200` adresindedir. İlk başlangıçta veritabanı yoksa SQLite dosyası oluşturulur ve EF Core migration'ları otomatik uygulanır (`CertificateDiscovery:ApplyMigrationsOnStartup=true`).

İlk kullanıcı `Admin / Admin123` değerleridir. İlk oturumdan hemen sonra sağ üstteki kullanıcı menüsünden parolayı değiştirin. Compose içindeki Vault dev modu ve `root` token yalnızca yerel geliştirme içindir.

## 2. Roller ve ana menü

| Rol | Yetki |
|---|---|
| `Admin` | Keşif, entegrasyon, sertifika talebi, deployment, agent, worker, kullanıcı ve ayar yönetimi |
| `Read` | Dashboard, Assets, Certificates ve Scan Jobs için salt okunur erişim |

Ana modüller:

- **Dashboard:** Sertifika sağlığı, yaklaşan sona erme tarihleri, varlık sayıları ve son tarama durumu.
- **Assets:** Bilinen TLS uçları; host, port, protokol, tarama aralığı ve etkinlik durumu.
- **Certificates:** Keşfedilen public sertifikaların fingerprint, issuer, SAN, geçerlilik ve bağlı varlık envanteri.
- **Scan Jobs:** Manuel/zamanlanmış taramaların kuyruğu, sonucu ve hata ayrıntıları.
- **Network Discovery:** CIDR aralığındaki bilinmeyen TLS uçlarını bulur ve seçilen sonuçları Asset'e dönüştürür.
- **Vault Discovery:** Vault PKI/KV içeriğini sertifika envanterine alır.
- **Certificate Requests:** ACME DNS-01 ile talep, doğrulama, issuance, Vault'a kaydetme ve yenileme.
- **Deployments:** Vault'taki yönetilen sertifikayı hedefe dağıtır, doğrular ve gerektiğinde geri alır.
- **Integrations:** Vault, ACME ve DNS sağlayıcılarını yönetir.
- **Workers:** Dağıtık tarama worker'larının heartbeat ve durumunu gösterir.
- **Deployment Agents:** Microsoft IIS agent kayıt, onay, durum ve iptal işlemleri.
- **Users / Application Settings:** Kullanıcılar, scheduler, alarm eşikleri ve eşzamanlı tarama sınırı.

## 3. Envanter ve keşif

### Asset eklemek ve taramak

1. **Assets > New asset** seçin.
2. Host, port ve protokolü (`HTTPS`, `TLS`, `SMTPS`, `IMAPS`, `POP3S`, `LDAPS`) girin.
3. Zamanlanmış tarama kullanılacaksa interval ve etkinlik durumunu belirleyin.
4. Kaydedin ve **Scan** ile ilk taramayı başlatın.
5. Sonucu **Scan Jobs**, sertifikayı **Certificates** ekranından inceleyin.

### Ağ keşfi

**Network Discovery** altında ad, IPv4 CIDR, portlar, timeout ve concurrency girin. Güvenlik nedeniyle aralık `/16`–`/32` ile sınırlıdır. Varsayılan portlar `443, 8443, 9443, 465, 993, 995, 636` değerleridir. Sonuçtaki güvenilir uçları **Promote to asset** ile kalıcı envantere alın.

### Vault keşfi

Önce **Integrations** altında Vault sunucusu tanımlayın. Ardından **Vault Discovery** ile KV v2 path veya PKI mount taraması başlatın. Discovery/Asset kaynaklı public sertifika envanteri DB'de tutulabilir; yönetilen ve private key'i bulunan sertifikalarda kaynak doğrusu yalnızca Vault'tur.

## 4. Entegrasyonlar ve sertifika talebi

### Vault

Vault URL, mount/path ve kimlik bilgisini tanımlayın. Üretimde token'ı kaynak koda veya hedef JSON'una yazmayın; kalıcı Data Protection anahtarları ve uygun secret provider kullanın.

### ACME ve DNS

1. Bir ACME provider oluşturun; ilk denemelerde Let's Encrypt Staging önerilir.
2. Hesabı kaydedin; Sectigo kullanılıyorsa EAB bilgilerini girin.
3. DNS-01 için Manual, Cloudflare, AWS Route53 veya Azure DNS sağlayıcısını oluşturun.
4. **Certificate Requests > New request** ile domain, SAN'lar, ACME/DNS/Vault seçimleri ve Vault secret path girin.
5. Challenge başlatın, TXT kaydını yayınlayın, doğrulayın ve sertifikayı üretin.

Başarılı issuance/renewal her seferinde Vault KV'de yeni bir sürüm oluşturur. DB yalnızca yaşam döngüsü durumu, fingerprint ve Vault referansı gibi metadata tutar; yönetilen sertifikanın PEM/PFX/private key içeriği DB'ye yazılmaz. Deployment sertifika paketini her zaman seçilen talebin Vault sürümünden okur.

## 5. Deployment kullanımı

### Hedef oluşturma

**Deployments > New target** altında hedef tipini seçin ve **Apply target template** ile güvenli şablonu yükleyin. `Secret` alanı hedefe göre korumalı credential/token içindir; sertifika materyali değildir.

Desteklenen P5 hedefleri:

| Hedef | Kullanım |
|---|---|
| Vault KV | Sertifikayı versioned KV secret olarak yazar, fingerprint doğrular, önceki sürüme dönebilir |
| File System Export | PEM/fullchain/key/PFX'i atomik yazar; izin, yedek ve rollback uygular |
| Kubernetes | `kubernetes.io/tls` Secret oluşturur/günceller; metadata ve resourceVersion davranışını korur |
| Microsoft IIS | Seçilen `winDeployAgent.exe` üzerinden binding veya Central Certificate Store dağıtımı |
| NGNIX | SSH ile atomik dosya değişimi, `nginx -t`, allowlist reload ve TLS doğrulaması |
| Apache Web Server | SSH ile dosya değişimi, `apachectl configtest`, allowlist reload ve doğrulama |
| AWS ACM | Workload/default credential chain veya AssumeRole ile import/update |
| Azure Key Vault | PFX/PEM import eder ve yeni Azure Key Vault version oluşturur |
| Azure Application Gateway | Versionless Key Vault secret referansı veya Vault kaynaklı doğrudan PFX yükleme |

HA Proxy, Traefik, Azure App Service ve AWS Load Balancer seçenekleri veri modelinde görünse de P5 kapsamında somut deployer bulunmaz; üretim hedefi olarak kullanmayın.

### Microsoft IIS agent

Agent ayrı `agents/winDeployAgent/winDeployAgent.sln` solution'ıdır ve Windows Service olarak kurulur.

1. Windows makinede installer'ı çalıştırıp Central URL ve agent adını yapılandırın.
2. Agent ilk çalışmada device-code tarzı registration exchange başlatır.
3. Central'da **Deployment Agents** ekranından makine, approval code ve public-key fingerprint'i doğrulayıp onaylayın.
4. Agent onayı tüketir, kalıcı kimliğini DPAPI machine scope ile korur ve heartbeat/polling'e başlar.
5. **Deployments > New target > Microsoft IIS** seçerken kayıtlı online/busy agent'ı dropdown'dan seçin.
6. Site, HTTPS binding, hostname, SNI, store ve deployment mode alanlarını şablonda düzenleyin.

Agent outbound-only çalışır, yalnızca kendisine atanmış işi claim eder ve kısa ömürlü şifrelenmiş bundle'ı kullanır. Central key/PFX parolasını DB'de saklamaz. Agent arbitrary PowerShell çalıştırmaz.

Binding örneği:

```json
{
  "siteName": "local.ertugrulkara.com",
  "bindingProtocol": "https",
  "bindingIpAddress": "*",
  "bindingPort": 443,
  "bindingHost": "local.ertugrulkara.com",
  "sniEnabled": true,
  "certificateStoreName": "My",
  "certificateStoreLocation": "LocalMachine",
  "deploymentMode": "Binding",
  "applicationPool": "DefaultAppPool",
  "restartApplicationPool": false
}
```

### Policy ve doğrulama

**New policy** ekranında retry, approval, automatic deployment ve rollback davranışını belirleyin. Çok düğümlü sistemlerde:

- `All`: bütün endpoint'ler yeni fingerprint'i sunmalı.
- `Any`: en az bir başarılı endpoint yeterlidir.
- `Percentage`: belirlenen yüzde ve minimum başarılı node birlikte sağlanmalıdır.

Attempts, interval ve timeout yayılım gecikmesini yönetir. Karışık eski/yeni sertifika görülürse durum `PartiallyVerified` olur; policy seçimine göre rollback tetiklenir.

### Deployment başlatma ve izleme

1. **Deploy certificate** seçin.
2. Dropdown'dan yalnızca `StoredInVault` durumundaki sertifikayı seçin.
3. Target ve policy seçip oluşturun.
4. Approval gerekiyorsa detay ekranında onaylayın.
5. `Prechecking → BackingUp → Deploying → Activating → Verifying` aşamalarını izleyin.
6. Detay ekranından internal/external endpoint sonucu, fingerprint, süre, retry ve rollback sonucunu kontrol edin.

## 6. Operasyon ve gözlemlenebilirlik

- `/health/live`: proses canlılık kontrolü.
- `/health/ready`: uygulama bağımlılıkları için readiness.
- `/metrics`: sertifika envanteri yanında deployment başarı/başarısızlık, retry, rollback, verification ve aşama süreleri.
- `/swagger`: REST API keşfi.

Metrik label'larında domain, target adı, endpoint, fingerprint veya sertifika içeriği bulunmaz. Worker API isteklerinde `X-Worker-Api-Key` kullanılır.

## 7. Günlük yönetim

- Dashboard ve sona erme eşiklerini günlük izleyin.
- `Stale/Offline/Revoked` IIS agent'larını araştırın.
- Başarısız ve `PartiallyVerified` deployment ayrıntılarını kontrol edin.
- Vault version retention, audit log ve backup politikasını uygulayın.
- SQLite volume, Data Protection key ring ve Vault verisini birlikte yedekleyin.
- Upgrade öncesinde yedek alın; yeni sürüm açılışında migration uygulanmasını ve `/health/ready` sonucunu doğrulayın.

## 8. Sorun giderme

| Belirti | Kontrol |
|---|---|
| UI açılmıyor | `docker compose ps`, web container logu, 8080 port çakışması |
| Worker iş almıyor | API URL/key, heartbeat, worker adı ve scheduler |
| ACME doğrulama bekliyor | TXT kaydı, authoritative DNS yayılımı ve provider credential |
| Sertifika deployment listesinde yok | Talebin `StoredInVault` olması ve Vault referansının erişilebilirliği |
| IIS agent ilk kayıtta bekliyor | Central'daki pending exchange'i onaylayın; unattended kurulum dışında statik registration token gerekmez |
| IIS agent offline | Central URL/TLS trust, service hesabı, DPAPI identity ve outbound erişim |
| SSH precheck başarısız | Vault SSH key referansı, pinned host fingerprint, kullanıcı/sudo ve dosya izinleri |
| Verification mismatch | DNS/LB node yayılımı, SNI hostname, endpoint listesi ve quorum |
| Otomatik rollback | Deployment detayında activation/verification nedeni ve rollback outcome |

## 9. Güvenlik kontrol listesi

- Varsayılan admin parolasını ve tüm örnek secret'ları değiştirin.
- Üretimde HTTPS, güvenli cookie, kalıcı Data Protection ve kurumsal Vault kullanın.
- Worker ve agent ağ erişimini minimuma indirin; CIDR taramasını yalnızca yetkili ağlarda çalıştırın.
- Kubernetes'te namespace-scoped minimum RBAC, AWS/Azure'da workload identity tercih edin.
- SSH host key pinning'i zorunlu tutun; hedef JSON'una private key veya serbest komut koymayın.
- Private key'i bulunan yönetilen sertifikalarda Vault'u tek source of truth olarak koruyun.

İleri entegrasyon ayrıntıları için [Enterprise DNS](../integrations/enterprise-dns.md), [Sectigo ACME](../integrations/sectigo-acme.md) ve [deployment mimarisi](../architecture/certificate-deployment-architecture.md) dokümanlarına bakın.
