"""Libellés des contrôles issus des règles de classement."""
TYPES = {
    "synology-backup": "Sauvegarde Synology", "synology-abb": "Active Backup for Business",
    "synology-integrity": "Intégrité de la sauvegarde", "synology-restore": "Restauration Synology",
    "synology-replication": "Réplication Synology", "synology-snapshot": "Instantané Synology",
    "synology-disks": "Santé des disques", "synology-capacity": "Capacité du volume",
    "synology-abb-connectivity": "Connexion Active Backup", "synology-ha": "Haute disponibilité Synology",
    "synology-scheduler": "Tâche planifiée Synology", "synology-log": "Journal Synology",
    "synology-dsm-update": "Mise à jour DSM", "synology-cms": "Connexion Synology CMS",
    "synology-firewall": "Pare-feu Synology", "account-security": "Sécurité du compte",
    "pve": "Sauvegarde de VM Proxmox", "pbs": "Maintenance Proxmox Backup",
    "pve-ha": "Haute disponibilité Proxmox", "pmg": "Ressources de la passerelle mail",
    "uptime": "Disponibilité", "openvas": "Scan OpenVAS", "wazuh": "Détection Wazuh",
    "ups": "État de l’onduleur", "ups-monitoring": "Supervision de l’onduleur",
    "ups-snmp": "Accès SNMP à l’onduleur", "printer": "État de l’imprimante",
    "github-actions": "Exécution GitHub Actions", "custom": "Contrôle personnalisé",
}
PBS_TYPES = {"verification": "Vérification PBS", "sync": "Synchronisation PBS",
             "sync-local": "Synchronisation locale PBS", "prune": "Rétention PBS",
             "garbage-collection": "Nettoyage PBS"}


def check_type(key):
    parts = key.split("|")
    if parts[0] == "missing":
        return "Réception du rapport"
    if parts[0] == "pbs" and len(parts) > 2:
        return PBS_TYPES.get(parts[2], TYPES["pbs"])
    return TYPES.get(parts[0], "Autre contrôle")
