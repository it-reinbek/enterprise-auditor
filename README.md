# Enterprise Security Auditor & Mitigation Tool (`enterprise-audit.sh`)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Audit Target: Java, VMware, Cisco](https://img.shields.io/badge/Target-Enterprise%20Infrastructure-orange.svg)](#)
[![Vulnerabilities: CISA KEV & Java4Shell](https://img.shields.io/badge/Vulnerabilities-2026%20KEV%20%26%20Java4Shell-red.svg)](#)

---

## 🇩🇪 Deutsche Beschreibung

Eigenständiges Bash-Audit- und Notfall-Remediation-Tool zur Erkennung und Härtung von unternehmensweiten Infrastrukturen gegen kritische Sicherheitslücken des Jahres 2026.

### 🔍 Erkannte Schwachstellen
* **OpenJDK / Java – „Java4Shell“ (CVE-2026-114938):** Integer-Underflow im AVX-512 VBMI Base64-Decoder von OpenJDK (Java 17, 21, 25). Führt zu Heap-Out-of-Bounds-Schreibzugriffen und unauthentifizierter Remote Code Execution (RCE) in Applikationen wie Keycloak, Jira oder Jenkins.
* **VMware vCenter Server (CVE-2026-123890):** Authentication Bypass im VMware Directory Service (vmdir) über RPC-Aufrufe an den Ports 389/636 (CISA KEV / VMSA-2026-0009).
* **Cisco Expressway Gateways (CVE-2026-76466):** Fest verdrahtete Zugangsdaten in Cluster-Komponenten zur unauthentifizierten Root-Kommandoausführung.
* **Apache Roller CMS (CVE-2026-129448):** Pre-Authentication Remote Code Execution über unsichere Deserialisierung an XML-RPC-Schnittstellen.

### 🚀 Schnellstart

```bash
# In das Projektverzeichnis wechseln
cd enterprise-auditor

# Sicherstellen, dass das Skript ausführbar ist
chmod +x enterprise-audit.sh

# Reiner Audit-Scan (ohne Menü, ideal für CI/CD, Scripts und Monitoring)
# Kann ohne Root-Rechte ausgeführt werden:
./enterprise-audit.sh --audit
# alternativ:
./enterprise-audit.sh --no-menu

# Interaktives Tool mit Untermenüs und Notfall-Mitigation (Root-Rechte erforderlich)
sudo ./enterprise-audit.sh

# Hilfe und verfügbare Optionen anzeigen
./enterprise-audit.sh --help
```

### 📋 Funktionen
* **Modulare Untermenüs:** Spezifische Audit- und Härtungsbereiche für Java/JVM, VMware vCenter, Cisco Gateways und Enterprise Java-Apps.
* **Automatischer CPU- & JVM-Check:** Erkennung, ob die CPU den gefährdeten `avx512vbmi`-Befehlssatz unterstützt und ob die installierte Java-Version gepatcht ist.
* **Reversible Notfall-Mitigation:**
  - **JVM:** Globales Setzen von `-XX:-UseBASE64Intrinsics` via Drop-in (`/etc/profile.d/java4shell-mitigation.sh` und `/etc/environment`).
  - **VMware:** Automatische `iptables`-Isolation der vmdir-Ports 389 und 636 gegen externe Zugriffe (nur Localhost 127.0.0.1 erlaubt).
* **Berichtsexport:** Generierung von Audit-Reports nach `/var/log/enterprise-audit-report.txt` (über Menüpunkt 5 oder via Ausgabeumleitung bei `--audit`).

### ⚙️ Voraussetzungen
* Linux-Betriebssystem mit `bash` (Version 4+)
* Standard-Werkzeuge: `grep`, `ps`, `find`
* Für Netzwerk- und Portprüfungen: `ss` oder `netstat`
* Für Firewall-Mitigationen: `iptables`
* Root-Rechte (`sudo`) werden ausschließlich für die Notfall-Mitigationen und Systemhärtungen benötigt; der reine Audit-Scan läuft auch als unprivilegierter Benutzer.

### 📄 Lizenz
Dieses Projekt ist unter der MIT-Lizenz veröffentlicht. Weitere Details siehe [LICENSE](LICENSE).
