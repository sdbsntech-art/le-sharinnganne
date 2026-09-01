#!/bin/bash
# ══════════════════════════════════════════
# SHARINNGANNE — Script de Sécurité Avancé
# Intégrité SHA-256 · Chiffrement GPG · Audit Système
# ══════════════════════════════════════════

set -euo pipefail

# ── Configuration ──
SECURE_DIR="${SECURE_DIR:-/home/user/secure_data}"
LOG_FILE="${LOG_FILE:-/home/user/security_logs.log}"
HASH_DB="${HASH_DB:-/home/user/.sharinnganne_hashes.db}"
GPG_PASSPHRASE="${GPG_PASSPHRASE:-}"
DATE=$(date '+%Y-%m-%d %H:%M:%S')
ALERT_COUNT=0

# ── Couleurs Terminal ──
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${CYAN}[SHARINNGANNE]${NC} $1"; echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"; }
alert() { echo -e "${RED}[⚠ ALERTE]${NC} $1"; echo "$(date '+%Y-%m-%d %H:%M:%S') - [ALERTE] $1" >> "$LOG_FILE"; ALERT_COUNT=$((ALERT_COUNT + 1)); }
ok() { echo -e "${GREEN}[✓]${NC} $1"; echo "$(date '+%Y-%m-%d %H:%M:%S') - [OK] $1" >> "$LOG_FILE"; }

# ══════════════════════════════════════════
# 1. VÉRIFICATION D'INTÉGRITÉ SHA-256
# ══════════════════════════════════════════
integrity_check() {
    log "=== VÉRIFICATION D'INTÉGRITÉ DES FICHIERS ==="

    if [ ! -d "$SECURE_DIR" ]; then
        mkdir -p "$SECURE_DIR"
        log "Dossier sécurisé créé : $SECURE_DIR"
    fi

    local file_count=0
    local modified_count=0

    for file in "$SECURE_DIR"/*; do
        [ -f "$file" ] || continue
        file_count=$((file_count + 1))

        current_hash=$(sha256sum "$file" | awk '{print $1}')
        filename=$(basename "$file")

        # Comparer avec le hash précédent stocké
        if [ -f "$HASH_DB" ]; then
            stored_hash=$(grep "^${filename}:" "$HASH_DB" 2>/dev/null | cut -d: -f2 || echo "")
            if [ -n "$stored_hash" ] && [ "$stored_hash" != "$current_hash" ]; then
                alert "FICHIER MODIFIÉ DÉTECTÉ : $filename"
                alert "  Ancien hash : $stored_hash"
                alert "  Nouveau hash: $current_hash"
                modified_count=$((modified_count + 1))
            elif [ -z "$stored_hash" ]; then
                ok "Nouveau fichier enregistré : $filename"
            else
                ok "Intégrité vérifiée : $filename"
            fi
        fi

        # Mettre à jour la base de hash
        if [ -f "$HASH_DB" ]; then
            sed -i "/^${filename}:/d" "$HASH_DB" 2>/dev/null || true
        fi
        echo "${filename}:${current_hash}" >> "$HASH_DB"
    done

    log "Fichiers analysés : $file_count | Modifications détectées : $modified_count"
}

# ══════════════════════════════════════════
# 2. AUDIT DE SÉCURITÉ SYSTÈME
# ══════════════════════════════════════════
system_audit() {
    log "=== AUDIT DE SÉCURITÉ SYSTÈME ==="

    # Vérifier les ports ouverts
    log "[PORTS] Scan des ports ouverts..."
    if command -v ss &>/dev/null; then
        open_ports=$(ss -tlnp 2>/dev/null | grep LISTEN | wc -l)
        log "Ports en écoute : $open_ports"
        ss -tlnp 2>/dev/null | grep LISTEN >> "$LOG_FILE"
    elif command -v netstat &>/dev/null; then
        open_ports=$(netstat -tlnp 2>/dev/null | grep LISTEN | wc -l)
        log "Ports en écoute : $open_ports"
    fi

    # Vérifier les connexions SSH actives
    log "[SSH] Vérification des sessions SSH..."
    ssh_sessions=$(who 2>/dev/null | wc -l)
    if [ "$ssh_sessions" -gt 1 ]; then
        alert "Sessions actives multiples détectées : $ssh_sessions"
        who >> "$LOG_FILE"
    else
        ok "Sessions SSH : $ssh_sessions (normal)"
    fi

    # Vérifier les tentatives de connexion échouées
    if [ -f /var/log/auth.log ]; then
        failed_logins=$(grep -c "Failed password" /var/log/auth.log 2>/dev/null || echo "0")
        if [ "$failed_logins" -gt 10 ]; then
            alert "Tentatives de connexion échouées : $failed_logins (seuil dépassé !)"
        else
            ok "Tentatives échouées : $failed_logins"
        fi
    fi

    # Vérifier les processus suspects
    log "[PROCESSUS] Analyse des processus actifs..."
    suspicious_procs=$(ps aux 2>/dev/null | grep -iE "(nmap|nikto|hydra|sqlmap|metasploit|msfconsole|john|hashcat)" | grep -v grep | wc -l)
    if [ "$suspicious_procs" -gt 0 ]; then
        alert "Processus de pentest détectés en cours d'exécution : $suspicious_procs"
        ps aux | grep -iE "(nmap|nikto|hydra|sqlmap|metasploit|msfconsole|john|hashcat)" | grep -v grep >> "$LOG_FILE"
    else
        ok "Aucun outil d'attaque actif détecté"
    fi

    # Vérifier les permissions sensibles
    log "[PERMISSIONS] Vérification des fichiers sensibles..."
    if [ -f /etc/passwd ]; then
        passwd_perms=$(stat -c '%a' /etc/passwd 2>/dev/null || echo "unknown")
        if [ "$passwd_perms" != "644" ] && [ "$passwd_perms" != "unknown" ]; then
            alert "Permissions /etc/passwd anormales : $passwd_perms (attendu: 644)"
        else
            ok "Permissions /etc/passwd : $passwd_perms"
        fi
    fi

    # Vérifier les fichiers SUID (escalade de privilèges)
    log "[SUID] Recherche de fichiers SUID..."
    suid_count=$(find / -perm -4000 -type f 2>/dev/null | wc -l)
    log "Fichiers SUID trouvés : $suid_count"
}

# ══════════════════════════════════════════
# 3. SCAN RÉSEAU LOCAL
# ══════════════════════════════════════════
network_scan() {
    log "=== SCAN RÉSEAU ==="

    # IP locale
    local_ip=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "inconnu")
    log "IP locale : $local_ip"

    # Interfaces réseau
    if command -v ip &>/dev/null; then
        interfaces=$(ip -br link show 2>/dev/null | awk '{print $1, $2}')
        log "Interfaces réseau :"
        echo "$interfaces" >> "$LOG_FILE"
    fi

    # Connexions actives suspectes
    if command -v ss &>/dev/null; then
        foreign_conns=$(ss -tnp 2>/dev/null | grep ESTAB | grep -v "127.0.0.1" | wc -l)
        log "Connexions externes actives : $foreign_conns"
        if [ "$foreign_conns" -gt 20 ]; then
            alert "Nombre élevé de connexions externes : $foreign_conns"
        fi
    fi

    # Vérifier le DNS
    log "[DNS] Test de résolution DNS..."
    if nslookup google.com &>/dev/null; then
        ok "Résolution DNS fonctionnelle"
    else
        alert "Résolution DNS en échec — réseau compromis ?"
    fi
}

# ══════════════════════════════════════════
# 4. CHIFFREMENT DES LOGS GPG
# ══════════════════════════════════════════
encrypt_logs() {
    log "=== CHIFFREMENT DES LOGS ==="

    if ! command -v gpg &>/dev/null; then
        alert "GPG non installé — les logs restent en clair !"
        echo -e "${YELLOW}Installez GPG : sudo apt install gnupg${NC}"
        return 1
    fi

    if [ ! -f "$LOG_FILE" ]; then
        alert "Fichier de logs introuvable : $LOG_FILE"
        return 1
    fi

    local encrypted_file="${LOG_FILE}.gpg"
    local backup_file="${LOG_FILE}.$(date '+%Y%m%d_%H%M%S').bak"

    # Sauvegarde avant chiffrement
    cp "$LOG_FILE" "$backup_file"

    # Chiffrement avec passphrase
    if [ -n "$GPG_PASSPHRASE" ]; then
        gpg --batch --yes --passphrase "$GPG_PASSPHRASE" --symmetric --cipher-algo AES256 -o "$encrypted_file" "$LOG_FILE"
    else
        gpg --batch --yes --symmetric --cipher-algo AES256 -o "$encrypted_file" "$LOG_FILE"
    fi

    if [ $? -eq 0 ]; then
        ok "Logs chiffrés avec AES-256 : $encrypted_file"
        # Suppression sécurisée du fichier en clair
        if command -v shred &>/dev/null; then
            shred -vfz -n 3 "$LOG_FILE" 2>/dev/null
            ok "Logs en clair détruits (shred 3 passes)"
        else
            rm -f "$LOG_FILE"
            ok "Logs en clair supprimés"
        fi
        rm -f "$backup_file"
    else
        alert "Échec du chiffrement — logs conservés en clair"
        mv "$backup_file" "$LOG_FILE"
    fi
}

# ══════════════════════════════════════════
# 5. RAPPORT FINAL
# ══════════════════════════════════════════
generate_report() {
    echo ""
    echo -e "${CYAN}══════════════════════════════════════════${NC}"
    echo -e "${CYAN}   SHARINNGANNE — RAPPORT DE SÉCURITÉ${NC}"
    echo -e "${CYAN}══════════════════════════════════════════${NC}"
    echo -e "  Date     : ${DATE}"
    echo -e "  Dossier  : ${SECURE_DIR}"
    echo -e "  Alertes  : ${RED}${ALERT_COUNT}${NC}"
    echo ""

    if [ "$ALERT_COUNT" -eq 0 ]; then
        echo -e "  ${GREEN}✅ SYSTÈME SÉCURISÉ — Aucune menace détectée${NC}"
    elif [ "$ALERT_COUNT" -lt 5 ]; then
        echo -e "  ${YELLOW}⚠️  ATTENTION — $ALERT_COUNT alerte(s) nécessitent une vérification${NC}"
    else
        echo -e "  ${RED}🚨 DANGER — $ALERT_COUNT alertes critiques détectées !${NC}"
    fi

    echo -e "${CYAN}══════════════════════════════════════════${NC}"
    echo ""
}

# ══════════════════════════════════════════
# EXÉCUTION PRINCIPALE
# ══════════════════════════════════════════
main() {
    echo -e "${CYAN}🔴 SHARINNGANNE Security Audit v3.0${NC}"
    echo ""

    # Créer le fichier de logs
    touch "$LOG_FILE"
    log "Démarrage de l'audit de sécurité SHARINNGANNE"

    # Exécuter tous les modules
    integrity_check
    system_audit
    network_scan

    # Rapport
    generate_report

    # Chiffrer les logs (dernière étape)
    encrypt_logs

    echo -e "${GREEN}Audit terminé. Logs chiffrés et sécurisés.${NC}"
}

# Lancer si exécuté directement
if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
    echo "Usage: ./security_audit.sh [OPTIONS]"
    echo ""
    echo "  SECURE_DIR=/path     Dossier à surveiller (défaut: /home/user/secure_data)"
    echo "  LOG_FILE=/path       Fichier de logs (défaut: /home/user/security_logs.log)"
    echo "  GPG_PASSPHRASE=xxx   Passphrase pour le chiffrement GPG"
    echo ""
    echo "Exemple: SECURE_DIR=/var/www GPG_PASSPHRASE=mysecret ./security_audit.sh"
    exit 0
fi

main "$@"
