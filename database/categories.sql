-- ============================================================================
-- SIEM AFRICA - Module 2
-- database/categories.sql
-- ============================================================================
-- Les 10 catégories de classification des attaques.
-- Référentiel statique alimenté une seule fois lors de l'installation.
-- ============================================================================

INSERT OR IGNORE INTO signature_categories (id, code, name, description, description_fr, icon, color_hex, display_order, is_active) VALUES

(1, 'BRUTE_FORCE', 'Brute Force / Authentification',
 'Repeated automated attempts to guess credentials (SSH, RDP, web admin, MySQL, FTP). Indicator: many failed authentications from same source IP in short time window.',
 'Tentatives automatisées répétées pour deviner des identifiants (SSH, RDP, web admin, MySQL, FTP). Indicateur : nombreux échecs d''authentification depuis une même IP source en peu de temps.',
 'key', '#E74C3C', 1, 1),

(2, 'RECONNAISSANCE', 'Reconnaissance / Scans',
 'Discovery activity preceding a real attack. The attacker maps the target infrastructure (open ports, exposed services, known vulnerabilities). Common tools: nmap, masscan, nikto.',
 'Activité de découverte précédant une vraie attaque. L''attaquant cartographie l''infrastructure cible (ports ouverts, services exposés, vulnérabilités connues). Outils courants : nmap, masscan, nikto.',
 'search', '#F39C12', 2, 1),

(3, 'WEB_EXPLOITATION', 'Exploitation Web (SQLi, XSS, RCE)',
 'Attacks targeting web applications: SQL injection, XSS (Cross-Site Scripting), Remote Code Execution, file inclusion (LFI/RFI), command injection. Goal: data exfiltration or server takeover.',
 'Attaques visant les applications web : injection SQL, XSS, exécution de code à distance (RCE), inclusion de fichiers (LFI/RFI), injection de commandes. Objectif : exfiltration de données ou prise de contrôle du serveur.',
 'globe', '#C0392B', 3, 1),

(4, 'MALWARE', 'Malware / Trojans',
 'Malicious software detected on systems: trojans, viruses, rootkits, backdoors, command-and-control communications (C2). Detection via signature, hash, or behavior.',
 'Logiciels malveillants détectés sur les systèmes : trojans, virus, rootkits, backdoors, communications C2 (command-and-control). Détection par signature, hash, ou comportement.',
 'bug', '#8E44AD', 4, 1),

(5, 'RANSOMWARE', 'Ransomware',
 'Ransomware attacks: massive file encryption, ransom notes, communications with attacker servers. Indicators: rapid massive file modification, suspicious extensions (.locked, .crypto), ransom files.',
 'Attaques par rançongiciel : chiffrement massif de fichiers, notes de rançon, communications avec serveurs des attaquants. Indicateurs : modification massive et rapide de fichiers, extensions suspectes (.locked, .crypto), apparition de fichiers de rançon.',
 'lock', '#922B21', 5, 1),

(6, 'FIM', 'File Integrity Monitoring',
 'Unauthorized modification of critical system files: /etc/passwd, /etc/sudoers, configuration files, web application binaries. Often indicates active compromise or persistence.',
 'Modification non autorisée de fichiers système critiques : /etc/passwd, /etc/sudoers, fichiers de configuration, binaires d''applications web. Indique souvent une compromission active ou de la persistance.',
 'shield', '#16A085', 6, 1),

(7, 'PRIV_ESC', 'Privilege Escalation',
 'Attempts to gain higher privileges than initially granted: sudo abuse, su attempts, exploitation of local kernel vulnerabilities, SUID misconfiguration. Standard step in attack kill chain after initial access.',
 'Tentatives d''obtenir des privilèges plus élevés que ceux initialement accordés : abus de sudo, tentatives su, exploitation de vulnérabilités locales du kernel, mauvaise configuration SUID. Étape standard dans la chaîne d''attaque après l''accès initial.',
 'arrow-up', '#D35400', 7, 1),

(8, 'NETWORK_ATTACK', 'Network attacks (DDoS, ARP)',
 'Network-level attacks: distributed denial of service (DDoS), ARP spoofing, MAC flooding, DNS spoofing, MITM attacks. Goal: traffic disruption or interception.',
 'Attaques au niveau réseau : déni de service distribué (DDoS), ARP spoofing, MAC flooding, DNS spoofing, attaques MITM. Objectif : perturbation ou interception du trafic.',
 'zap', '#2980B9', 8, 1),

(9, 'CVE_EXPLOIT', 'Exploit CVE connus',
 'Exploitation of known vulnerabilities (CVE) in unpatched software: Log4Shell, Heartbleed, Shellshock, ProxyShell, PrintNightmare, Spring4Shell. Often targets internet-facing applications.',
 'Exploitation de vulnérabilités connues (CVE) dans des logiciels non patchés : Log4Shell, Heartbleed, Shellshock, ProxyShell, PrintNightmare, Spring4Shell. Cible souvent les applications exposées sur internet.',
 'alert-triangle', '#E67E22', 9, 1),

(10, 'PERSISTENCE', 'Anomalies système / Persistance',
 'Mechanisms used by attackers to maintain access: modification of cron tasks, adding services, registry keys (Windows), modification of .bashrc/.profile, suspicious systemd timers. Detection via FIM and audit log.',
 'Mécanismes utilisés par les attaquants pour maintenir l''accès : modification de tâches cron, ajout de services, clés de registre (Windows), modification de .bashrc/.profile, timers systemd suspects. Détection via FIM et journal d''audit.',
 'clock', '#7F8C8D', 10, 1);

-- ============================================================================
-- FIN categories.sql - 10 catégories insérées
-- ============================================================================
