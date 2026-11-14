# BLACKVEIL X — Advanced Cybersecurity Ecosystem & Isolated Sandbox Infrastructure

**BLACKVEIL X**, Python ve Rich tabanlı, Windows 10/11 (CMD & PowerShell) ve Linux/POSIX terminallerinde çalışan; Docker Engine sandbox altyapısı, 20 güvenlik modülü, AI Güvenlik Analisti, CTF & Görev/XP sistemi, SQLite merkezi veritabanı ve çoklu raporlama motoruna (TXT/JSON/CSV/PDF) sahip bütünsel bir siber güvenlik terminal ekosistemidir.

> **ONE TERMINAL. ONE ECOSYSTEM. INFINITE POSSIBILITIES.**

---

## Kurulum (Windows 10 / 11)

```cmd
install.bat
```
veya manuel olarak:
```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

### Çalıştırma
- Etkileşimli Terminal: `run.bat` veya `python main.py`
- Doğrudan CLI:
  ```cmd
  blackveil sandbox create --name linux-lab
  blackveil sandbox list
  blackveil threat lookup example.com
  blackveil integrity scan
  blackveil logs analyze
  blackveil audit system
  blackveil pcap summary capture.pcap
  blackveil deps audit
  blackveil ctf start CTF-01
  blackveil mission list
  blackveil report create --format pdf
  blackveil website scan https://example.com --export json
  blackveil website local https://example.com
  blackveil ipinfo 8.8.8.8
  blackveil ip local
  blackveil ip logs analyze access.log
  blackveil url check https://example.com
  blackveil ai config --api-key
  blackveil ai ask "Explain HSTS preload risks"
  blackveil computer search config --path . --ext .py
  blackveil computer startup
  blackveil search deep "CVE OpenSSL"
  ```

---

## Sistem Mimarisi
- `core/`: Komut ayrıştırıcı, yapılandırma, kısıtlı gizli anahtar deposu (`SecretsManager`), loglama, Rich terminal ve gizli veri maskelemeli `SessionRecorder`
- `database/`: Sürümlü migrasyon destekli merkezi SQLite (`data/blackveil.db`, Schema v3)
- `sandbox/`: Güvenlik sıkılaştırmalı Docker Engine sandbox yaşam döngüsü (`--cap-drop=ALL`, `no-new-privileges`, `--network=none`, CPU/RAM/PID limitleri, snapshot/restore, doğrulama denetimi) ve `ContainerInspector`
- `labs/`: Vulnerability Lab (`VULN-01..03`), CTF Engine (`CTF-01..03`), Red Team / Blue Team Purple Exercise
- `missions/`: Beginner / Intermediate / Advanced görevler, XP, Seviye, Rütbe ve Başarım sistemi
- `ai/`: `AISecurityAnalyst` (Gemini API etkileşimli sohbet, `ai ask`, güvenli `ai config --api-key`, timeout/retry ve çevrimdışı MITRE ATT&CK korelasyon motoru)
- `plugins/`: AST statik güvenlik denetimli, SHA-256 imzalı ve açık izin kontrollü Python eklenti motoru
- `automation/`: Çok adımlı tekrarlanabilir güvenlik playbook motoru
- `reports/`: TXT, JSON, CSV ve saf Python PDF 1.4 dışa aktarma motoru
- `modules/`: Website Intelligence, Local Website Environment, IP Intelligence, Malicious URL Detector, Local Computer Intelligence Search, External Intelligence Search Engine, Threat Intel, File Integrity Guard, Log Intelligence, Evidence Vault, Network Baseline, Config Auditor, Secret Scanner, Incident Engine, PCAP Analyzer, DNS Intel, Certificate Watcher, Dependency Guard, Knowledge Base, Network, Forensics, Password Lab, System Intel, War Room, Live Monitor
- `tests/`: Otomatik birim ve güvenlik politikası test paketi (`python -m unittest discover -s tests`)

---

## Güvenlik ve Yetki İlkeleri
- Docker bulunmuyorsa veya daemon kapalıysa açık hata mesajı verilir; Docker gerektirmeyen diğer tüm modüller kesintisiz çalışmaya devam eder.
- Sandbox konteynerleri asla `--privileged` çalıştırılmaz, host dosya sistemi bağlanmaz ve Docker socket aktarılmaz.
- Gizli anahtarlar kaynak kodunda saklanmaz; `ai config --api-key` ile eklenen anahtarlar geçmişe, oturum kaydına, `config.json` dosyasına veya raporlara yazılmaz.
- Opera tarayıcısı veya harici API anahtarları (`GEMINI_API_KEY`, `GOOGLE_SAFE_BROWSING_API_KEY`, `VT_API_KEY`, `GOOGLE_CSE_API_KEY`) sistemde mevcut değilse sahte sonuç üretilmez; eksik kontroller açıkça raporlanır.

