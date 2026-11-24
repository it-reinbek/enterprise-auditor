#!/usr/bin/env bash
#
# enterprise-audit.sh - Enterprise Infrastructure Security Auditor
# Audits enterprise environments for critical late-2026 vulnerabilities:
# - OpenJDK / Java "Java4Shell" (CVE-2026-114938)
# - VMware vCenter Directory Service Pre-Auth Bypass (CVE-2026-123890)
# - Cisco Expressway Hardcoded Credentials / Root Access (CVE-2026-76466)
# - Apache Roller XML-RPC Pre-Auth RCE (CVE-2026-129448)
#
set -euo pipefail

VERSION="1.0.0"
STATE_DIR="/var/lib/enterprise-auditor"
LOG_FILE="/var/log/enterprise-audit.log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

CRIT_COUNT=0
WARN_COUNT=0
OK_COUNT=0

init_storage() {
  if [ "$(id -u)" -eq 0 ]; then
    mkdir -p "${STATE_DIR}"
    chmod 700 "${STATE_DIR}"
  fi
}

print_header() {
  clear 2>/dev/null || true
  echo -e "${CYAN}======================================================================${NC}"
  echo -e "${BOLD}  Enterprise Security Auditor v${VERSION} (Java, VMware, Cisco, Apps)${NC}"
  echo -e "${CYAN}======================================================================${NC}"
  echo ""
}

# ==================== JAVA / OPENJDK (JAVA4SHELL) ====================

audit_java() {
  echo -e "${BOLD}[1] Auditierung: Java Runtime & OpenJDK (Java4Shell - CVE-2026-114938)${NC}"
  echo "----------------------------------------------------------------------"
  if ! command -v java >/dev/null 2>&1; then
    echo -e "${BLUE}[INFO]${NC} Kein Java / OpenJDK im globalen PATH gefunden."
    return 0
  fi

  local jver
  jver=$(java -version 2>&1 | head -n 1)
  echo -e "${BLUE}[INFO]${NC} Erkannte Java-Version: ${jver}"

  # Check CPU AVX-512 VBMI flag
  local has_vbmi=0
  if grep -qi "avx512_vbmi\|avx512vbmi" /proc/cpuinfo 2>/dev/null; then
    has_vbmi=1
  fi

  if [ "$has_vbmi" -eq 1 ]; then
    echo -e "${YELLOW}[WARN]${NC} CPU-Architektur unterstützt AVX-512 VBMI (betroffener Code-Pfad verfügbar)!"
  else
    echo -e "${GREEN}[ OK ]${NC} CPU unterstützt kein AVX-512 VBMI. Anfälliger ASM-Pfad hardwareseitig inaktiv."
  fi

  # Check version numbers for safe patch levels
  # Safe: >= 17.0.21.1, >= 21.0.13.1, >= 25.0.5.1
  local is_patched=0
  if echo "$jver" | grep -qE "21\.0\.13\.[1-9]|17\.0\.21\.[1-9]|25\.0\.5\.[1-9]"; then
    is_patched=1
  fi

  # Check if JVM mitigation flag is set in env
  local flag_active=0
  if [ -n "${JAVA_TOOL_OPTIONS:-}" ] && echo "$JAVA_TOOL_OPTIONS" | grep -q -- "-XX:-UseBASE64Intrinsics"; then
    flag_active=1
  elif [ -f /etc/profile.d/java4shell-mitigation.sh ]; then
    flag_active=1
  fi

  if [ "$is_patched" -eq 1 ]; then
    echo -e "${GREEN}[ OK ]${NC} Java Runtime ist auf offiziellem Patch-Stand gegen CVE-2026-114938."
    OK_COUNT=$((OK_COUNT + 1))
  elif [ "$flag_active" -eq 1 ]; then
    echo -e "${GREEN}[ OK ]${NC} Notfall-Mitigation aktiv: -XX:-UseBASE64Intrinsics ist gesetzt."
    OK_COUNT=$((OK_COUNT + 1))
  elif [ "$has_vbmi" -eq 1 ]; then
    echo -e "${RED}[CRIT]${NC} Ungepatchte Java-Version auf CPU mit AVX-512 VBMI ohne Schutz-Flags!"
    echo -e "       Risiko: Integer-Underflow im Base64-Decoder führt zu Memory Corruption / RCE."
    CRIT_COUNT=$((CRIT_COUNT + 1))
  else
    echo -e "${YELLOW}[WARN]${NC} Ungepatchtes Java erkannt, jedoch durch fehlendes AVX-512 VBMI CPU-Flag entschärft."
    WARN_COUNT=$((WARN_COUNT + 1))
  fi
  echo ""
}

apply_java_mitigation() {
  echo -e "${YELLOW}--> Aktiviere Notfall-Mitigation für Java (-XX:-UseBASE64Intrinsics)...${NC}"
  if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[FEHLER] Root-Rechte erforderlich.${NC}"
    return 1
  fi

  cat <<'EOF' > /etc/profile.d/java4shell-mitigation.sh
# Enterprise-Auditor: Emergency Mitigation for CVE-2026-114938
export JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS:-} -XX:-UseBASE64Intrinsics"
EOF
  chmod 644 /etc/profile.d/java4shell-mitigation.sh

  # Also add to /etc/environment if not present
  if ! grep -q "JAVA_TOOL_OPTIONS" /etc/environment 2>/dev/null; then
    echo 'JAVA_TOOL_OPTIONS="-XX:-UseBASE64Intrinsics"' >> /etc/environment
  fi

  echo "1" > "${STATE_DIR}/java_mitigated"
  echo -e "${GREEN}[ERFOLG] JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics systemweit hinterlegt.${NC}"
}

revert_java_mitigation() {
  echo -e "${YELLOW}--> Mache Java-Mitigation rückgängig...${NC}"
  rm -f /etc/profile.d/java4shell-mitigation.sh "${STATE_DIR}/java_mitigated" 2>/dev/null || true
  sed -i '/JAVA_TOOL_OPTIONS.*UseBASE64Intrinsics/d' /etc/environment 2>/dev/null || true
  echo -e "${GREEN}[ERFOLG] Java-Mitigation rückabgewickelt.${NC}"
}

# ==================== VMWARE VCENTER ====================

audit_vmware() {
  echo -e "${BOLD}[2] Auditierung: VMware vCenter / vmdir (CVE-2026-123890)${NC}"
  echo "----------------------------------------------------------------------"
  local exposed_ports=""

  # Check listening ports for VMware Directory Service: 389 (LDAP), 636 (LDAPS)
  if command -v ss >/dev/null 2>&1; then
    exposed_ports=$(ss -tlpn 2>/dev/null | grep -E ":(389|636)\s" || true)
  elif command -v netstat >/dev/null 2>&1; then
    exposed_ports=$(netstat -tlpn 2>/dev/null | grep -E ":(389|636)\s" || true)
  fi

  if [ -n "$exposed_ports" ]; then
    echo -e "${RED}[CRIT]${NC} Port 389 oder 636 (LDAP/vmdir) lauscht auf diesem System!"
    echo -e "       Befund:\n${exposed_ports}"
    echo -e "       Risiko: CVE-2026-123890 erlaubt unauthentifizierten Authentication Bypass auf vCenter."
    CRIT_COUNT=$((CRIT_COUNT + 1))
  else
    echo -e "${GREEN}[ OK ]${NC} Keine offenen vmdir/LDAP-Ports (389, 636) auf dem System festgestellt."
    OK_COUNT=$((OK_COUNT + 1))
  fi
  echo ""
}

apply_vmware_port_isolation() {
  echo -e "${YELLOW}--> Isoliere vmdir/LDAP-Ports (389/636) via iptables...${NC}"
  if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[FEHLER] Root-Rechte erforderlich.${NC}"
    return 1
  fi

  if command -v iptables >/dev/null 2>&1; then
    iptables -I INPUT -p tcp --dport 389 -s 127.0.0.1 -j ACCEPT
    iptables -I INPUT -p tcp --dport 636 -s 127.0.0.1 -j ACCEPT
    iptables -A INPUT -p tcp --dport 389 -j DROP
    iptables -A INPUT -p tcp --dport 636 -j DROP
    echo "1" > "${STATE_DIR}/vmware_isolated"
    echo -e "${GREEN}[ERFOLG] Externe Zugriffe auf Port 389 & 636 blockiert (nur Localhost erlaubt).${NC}"
  else
    echo -e "${RED}[FEHLER] iptables nicht gefunden.${NC}"
  fi
}

revert_vmware_port_isolation() {
  echo -e "${YELLOW}--> Mache Port-Isolation für VMware rückgängig...${NC}"
  if command -v iptables >/dev/null 2>&1; then
    iptables -D INPUT -p tcp --dport 389 -j DROP 2>/dev/null || true
    iptables -D INPUT -p tcp --dport 636 -j DROP 2>/dev/null || true
    iptables -D INPUT -p tcp --dport 389 -s 127.0.0.1 -j ACCEPT 2>/dev/null || true
    iptables -D INPUT -p tcp --dport 636 -s 127.0.0.1 -j ACCEPT 2>/dev/null || true
  fi
  rm -f "${STATE_DIR}/vmware_isolated" 2>/dev/null || true
  echo -e "${GREEN}[ERFOLG] VMware Port-Isolation rückabgewickelt.${NC}"
}

# ==================== CISCO EXPRESSWAY ====================

audit_cisco() {
  echo -e "${BOLD}[3] Auditierung: Cisco Expressway (CVE-2026-76466)${NC}"
  echo "----------------------------------------------------------------------"
  local cisco_procs
  cisco_procs=$(ps -ef | grep -iE "expressway|tandberg|cisco" | grep -v grep || true)

  if [ -n "$cisco_procs" ]; then
    echo -e "${RED}[CRIT]${NC} Cisco Expressway Dienste auf dem Host erkannt!"
    echo -e "       Risiko: CVE-2026-76466 (Hardcoded Credentials) ermöglicht unauthentifiziertes Root RCE."
    CRIT_COUNT=$((CRIT_COUNT + 1))
  else
    echo -e "${GREEN}[ OK ]${NC} Keine lokalen Cisco Expressway Instanzen auf diesem Linux-Host gefunden."
    OK_COUNT=$((OK_COUNT + 1))
  fi
  echo ""
}

# ==================== ENTERPRISE CMS & APPS ====================

audit_enterprise_apps() {
  echo -e "${BOLD}[4] Auditierung: Enterprise CMS & Java Apps (Apache Roller & Deserialization)${NC}"
  echo "----------------------------------------------------------------------"
  local roller_found=0
  for d in /opt /srv /var/lib/tomcat* /usr/share/tomcat*; do
    if [ -d "$d" ]; then
      if find "$d" -maxdepth 3 -name "*roller*.war" -o -name "*roller*.jar" 2>/dev/null | grep -q .; then
        roller_found=1
        break
      fi
    fi
  done

  if [ "$roller_found" -eq 1 ]; then
    echo -e "${RED}[CRIT]${NC} Apache Roller Installation lokal gefunden!"
    echo -e "       Risiko: CVE-2026-129448 XML-RPC Deserialization ermöglicht unauthentifiziertes RCE."
    CRIT_COUNT=$((CRIT_COUNT + 1))
  else
    echo -e "${GREEN}[ OK ]${NC} Keine lokalen Apache Roller Instanzen entdeckt."
    OK_COUNT=$((OK_COUNT + 1))
  fi

  # Check Keycloak / Jira / Jenkins services
  local ent_apps
  ent_apps=$(ps -ef | grep -iE "keycloak|jira|confluence|jenkins" | grep -v grep || true)
  if [ -n "$ent_apps" ]; then
    echo -e "${YELLOW}[WARN]${NC} Aktive Enterprise Java Applikationen (Keycloak/Jira/Jenkins) erkannt!"
    echo -e "       Hinweis: Diese Dienste sind potenzielle Ziele für Java4Shell (CVE-2026-114938)."
    WARN_COUNT=$((WARN_COUNT + 1))
  else
    echo -e "${GREEN}[ OK ]${NC} Keine aktiven Keycloak-, Jira- oder Jenkins-Prozesse registriert."
    OK_COUNT=$((OK_COUNT + 1))
  fi
  echo ""
}

# ==================== SUBMENUS ====================

submenu_java() {
  while true; do
    print_header
    echo -e "${BOLD}UNTERMENÜ: Java / OpenJDK (Java4Shell - CVE-2026-114938)${NC}"
    echo "---------------------------------------------------------"
    local st="Inaktiv [ ]"
    [ -f "${STATE_DIR}/java_mitigated" ] && st="${GREEN}Aktiv [x]${NC}"
    echo -e "Status JVM-Mitigation (-XX:-UseBASE64Intrinsics): ${st}"
    echo ""
    echo "  1) Java Live-Audit durchführen"
    echo "  2) Notfall-Mitigation aktivieren (Drop-in & Environment)"
    echo "  3) Notfall-Mitigation rückgängig machen (Rollback)"
    echo "  4) Zurück zum Hauptmenü"
    echo ""
    read -rp "Auswahl [1-4]: " jc
    case "$jc" in
      1) audit_java; read -rp "Drücken Sie [Enter] zum Fortfahren..." ;;
      2) apply_java_mitigation; read -rp "Drücken Sie [Enter] zum Fortfahren..." ;;
      3) revert_java_mitigation; read -rp "Drücken Sie [Enter] zum Fortfahren..." ;;
      4) break ;;
      *) echo "Ungültige Auswahl." ; sleep 1 ;;
    esac
  done
}

submenu_vmware() {
  while true; do
    print_header
    echo -e "${BOLD}UNTERMENÜ: VMware vCenter Isolation (CVE-2026-123890)${NC}"
    echo "------------------------------------------------------"
    local st="Inaktiv [ ]"
    [ -f "${STATE_DIR}/vmware_isolated" ] && st="${GREEN}Aktiv [x]${NC}"
    echo -e "Status Port-Isolation (389/636): ${st}"
    echo ""
    echo "  1) VMware vmdir/LDAP Live-Audit durchführen"
    echo "  2) Notfall-Port-Isolation aktivieren (iptables Drop extern)"
    echo "  3) Notfall-Port-Isolation rückgängig machen (Rollback)"
    echo "  4) Zurück zum Hauptmenü"
    echo ""
    read -rp "Auswahl [1-4]: " vc
    case "$vc" in
      1) audit_vmware; read -rp "Drücken Sie [Enter] zum Fortfahren..." ;;
      2) apply_vmware_port_isolation; read -rp "Drücken Sie [Enter] zum Fortfahren..." ;;
      3) revert_vmware_port_isolation; read -rp "Drücken Sie [Enter] zum Fortfahren..." ;;
      4) break ;;
      *) echo "Ungültige Auswahl." ; sleep 1 ;;
    esac
  done
}

run_full_audit() {
  print_header
  CRIT_COUNT=0
  WARN_COUNT=0
  OK_COUNT=0

  audit_java
  audit_vmware
  audit_cisco
  audit_enterprise_apps

  echo "======================================================================"
  echo -e "${BOLD}AUDIT-ZUSAMMENFASSUNG:${NC}"
  echo -e "  Kritische Befunde (CRIT): ${RED}${CRIT_COUNT}${NC}"
  echo -e "  Warnungen         (WARN): ${YELLOW}${WARN_COUNT}${NC}"
  echo -e "  Sichere Prüfungen ( OK ): ${GREEN}${OK_COUNT}${NC}"
  echo "======================================================================"
  echo ""
}

main_menu() {
  while true; do
    print_header
    echo -e "${BOLD}HAUPTMENÜ:${NC}"
    echo "  1) Gesamtes Enterprise-Audit durchführen (Java, VMware, Cisco, Apps)"
    echo "  2) Untermenü: Java / OpenJDK (Java4Shell CVE-2026-114938)"
    echo "  3) Untermenü: VMware vCenter / vmdir (CVE-2026-123890)"
    echo "  4) Untermenü: Cisco Expressway & Enterprise Apps"
    echo "  5) Revisions-Bericht exportieren (/var/log/enterprise-audit-report.txt)"
    echo "  q) Beenden"
    echo ""
    read -rp "Ihre Wahl: " mc
    case "$mc" in
      1) run_full_audit; read -rp "Drücken Sie [Enter] für das Menü..." ;;
      2) submenu_java ;;
      3) submenu_vmware ;;
      4)
        print_header
        audit_cisco
        audit_enterprise_apps
        read -rp "Drücken Sie [Enter] für das Menü..." ;;
      5)
        run_full_audit > /var/log/enterprise-audit-report.txt 2>&1 || true
        echo -e "${GREEN}[ERFOLG] Bericht nach /var/log/enterprise-audit-report.txt exportiert.${NC}"
        read -rp "Drücken Sie [Enter] für das Menü..." ;;
      q|Q) echo "Beende."; exit 0 ;;
      *) echo "Ungültige Option."; sleep 1 ;;
    esac
  done
}

init_storage

if [ "${1:-}" = "--audit" ] || [ "${1:-}" = "--no-menu" ]; then
  run_full_audit
  exit 0
elif [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  echo "Verwendung: $0 [--audit|--no-menu|-h|--help]"
  exit 0
else
  main_menu
fi
