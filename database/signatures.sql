-- ============================================================================
-- SIEM AFRICA - Module 2
-- database/signatures.sql
-- ============================================================================
-- 380 signatures de détection (190 Wazuh + 190 Snort)
-- L'id est le rule_id natif Wazuh ou le SID Snort.
-- Plages :
--   1-99999       : Wazuh natif
--   100000-999999 : Wazuh custom
--   1000000+      : Snort SID
-- ============================================================================

INSERT OR IGNORE INTO signatures (id, source, category_id, technique_id, name, description, description_fr, severity, confidence, recommended_action, remediation_fr, ai_context_keywords, is_active, is_noisy) VALUES
(5710, 'WAZUH', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110'), 'sshd: Failed login attempt', 'Single failed SSH authentication.', 'Tentative SSH échouée unique.', 'LOW', 70, 'MONITOR', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["sshd", "T1110"]', 1, 0),
(5712, 'WAZUH', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'sshd: Brute force attempt', '8+ failed SSH auths in 120s from same IP.', '8+ échecs SSH en 120s depuis la même IP.', 'HIGH', 90, 'BLOCK', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["sshd", "T1110.001"]', 1, 0),
(5713, 'WAZUH', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110'), 'sshd: Corrupted bytes', 'Corrupted bytes on SSH connection (fuzzing).', 'Bytes corrompus sur connexion SSH (fuzzing).', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["sshd", "T1110"]', 1, 0),
(5714, 'WAZUH', 9, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'sshd: SSH CRC-32 attack', 'CRC-32 compensation attack (CVE-2001-0144).', 'Attaque CRC-32 (CVE-2001-0144).', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• Bloquer l''IP attaquante.
• Vérifier la version du logiciel ciblé.

À vérifier :
• La CVE est-elle applicable à votre version ?
• Le serveur a-t-il été patché récemment ?

À corriger :
• Patcher d''urgence le logiciel concerné.
• apt upgrade ou yum update.
• Si exploitation réussie : forensics complet.', '["sshd", "T1190"]', 1, 0),
(5715, 'WAZUH', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1078'), 'sshd: Authentication success', 'Successful SSH login (audit).', 'Connexion SSH réussie (audit).', 'INFO', 100, 'MONITOR', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["sshd", "T1078"]', 1, 1),
(5716, 'WAZUH', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110'), 'sshd: Auth refused (auth_keys perms)', 'SSH auth refused due to authorized_keys permissions.', 'Auth SSH refusée (permissions authorized_keys).', 'LOW', 80, 'ALERT', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["sshd", "T1110"]', 1, 0),
(5720, 'WAZUH', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110'), 'sshd: Multiple auth failures (different sources)', 'Distributed brute force attempt.', 'Brute force distribué.', 'HIGH', 85, 'BLOCK', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["sshd", "T1110"]', 1, 0),
(5740, 'WAZUH', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110'), 'sshd: Disconnected before auth', 'Client disconnected before completing authentication.', 'Client déconnecté avant fin d''authentification.', 'LOW', 60, 'MONITOR', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["sshd", "T1110"]', 1, 1),
(5503, 'WAZUH', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110'), 'PAM: User login failed', 'Single PAM authentication failure.', 'Échec PAM unique.', 'LOW', 70, 'MONITOR', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["pam", "T1110"]', 1, 1),
(5551, 'WAZUH', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'PAM: Multiple failed logins', '5+ PAM auth failures in 10min.', '5+ échecs PAM en 10min.', 'HIGH', 85, 'BLOCK', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["pam", "T1110.001"]', 1, 0),
(5556, 'WAZUH', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110'), 'PAM: User account locked', 'Account locked after multiple failures.', 'Compte verrouillé après échecs multiples.', 'MEDIUM', 90, 'ALERT', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["pam", "T1110"]', 1, 0),
(5557, 'WAZUH', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110'), 'PAM: Account temporarily locked', 'Temporary lock by pam_faillock.', 'Verrouillage temporaire pam_faillock.', 'MEDIUM', 90, 'ALERT', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["pam", "T1110"]', 1, 0),
(5402, 'WAZUH', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1078'), 'sudo: Successful sudo execution', 'Sudo command executed successfully.', 'Commande sudo exécutée avec succès.', 'INFO', 100, 'MONITOR', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["sudo", "T1078"]', 1, 1),
(5403, 'WAZUH', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1548'), 'sudo: Failed sudo attempt', 'Failed sudo attempt (wrong password or no permission).', 'Tentative sudo échouée (mauvais MDP ou pas de permission).', 'MEDIUM', 80, 'ALERT', 'Action immédiate :
• Vérifier les commandes exécutées par cet utilisateur.
• Auditer ses connexions récentes.

À vérifier :
• Pourquoi cet utilisateur tente une élévation.
• Si action légitime (admin) ou suspecte.

À corriger :
• Réviser les permissions sudo (/etc/sudoers).
• Limiter les droits aux strict nécessaire (principe moindre privilège).
• Logger toutes commandes sudo.', '["sudo", "T1548"]', 1, 0),
(5404, 'WAZUH', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1548'), 'sudo: Multiple sudo failures', '3+ sudo failures from same user. Possible privilege escalation.', '3+ échecs sudo du même utilisateur. Élévation de privilège possible.', 'HIGH', 85, 'ALERT', 'Action immédiate :
• Vérifier les commandes exécutées par cet utilisateur.
• Auditer ses connexions récentes.

À vérifier :
• Pourquoi cet utilisateur tente une élévation.
• Si action légitime (admin) ou suspecte.

À corriger :
• Réviser les permissions sudo (/etc/sudoers).
• Limiter les droits aux strict nécessaire (principe moindre privilège).
• Logger toutes commandes sudo.', '["sudo", "T1548"]', 1, 0),
(5501, 'WAZUH', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1078'), 'PAM session opened', 'PAM session opened (login event).', 'Session PAM ouverte (événement de connexion).', 'INFO', 100, 'MONITOR', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["pam session opened", "T1078"]', 1, 1),
(60122, 'WAZUH', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110'), 'Windows: Logon failure (4625)', 'Windows authentication failure (Event ID 4625).', 'Échec d''authentification Windows (Event ID 4625).', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["windows", "T1110"]', 1, 0),
(60106, 'WAZUH', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.003'), 'Windows: Password spray attack', 'Same password tried on multiple accounts.', 'Même MDP testé sur plusieurs comptes.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["windows", "T1110.003"]', 1, 0),
(60204, 'WAZUH', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110'), 'Windows: RDP brute force', 'Multiple RDP authentication failures.', 'Multiples échecs d''authentification RDP.', 'HIGH', 85, 'BLOCK', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["windows", "T1110"]', 1, 0),
(60103, 'WAZUH', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1078'), 'Windows: Logon success after failures', 'Successful logon after failed attempts. Possible compromise.', 'Connexion réussie après échecs. Compromission possible.', 'HIGH', 85, 'ALERT', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["windows", "T1078"]', 1, 0),
(60111, 'WAZUH', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1078'), 'Windows: Logon with explicit credentials', 'Logon using explicit credentials (Event 4648).', 'Connexion avec credentials explicites (Event 4648).', 'MEDIUM', 70, 'MONITOR', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["windows", "T1078"]', 1, 0),
(60125, 'WAZUH', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110'), 'Windows: Account lockout (4740)', 'Account locked due to failed logons.', 'Compte verrouillé suite à échecs.', 'MEDIUM', 90, 'ALERT', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["windows", "T1110"]', 1, 0),
(60130, 'WAZUH', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1078'), 'Windows: Special privileges assigned', 'Special privileges assigned at logon (4672).', 'Privilèges spéciaux assignés à la connexion (4672).', 'MEDIUM', 75, 'MONITOR', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["windows", "T1078"]', 1, 0),
(60140, 'WAZUH', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110'), 'Windows: Kerberos auth failure', 'Kerberos authentication failure (4771).', 'Échec d''authentification Kerberos (4771).', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["windows", "T1110"]', 1, 0),
(60141, 'WAZUH', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110'), 'Windows: Kerberos pre-auth failure', 'Kerberos pre-authentication failure. Possible AS-REP roasting.', 'Échec pré-auth Kerberos. AS-REP roasting possible.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["windows", "T1110"]', 1, 0),
(60150, 'WAZUH', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110'), 'Windows: NTLM auth failure', 'NTLM authentication failure detected.', 'Échec d''authentification NTLM détecté.', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["windows", "T1110"]', 1, 0),
(5805, 'WAZUH', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110'), 'MySQL: Failed authentication', 'MySQL authentication failure.', 'Échec authentification MySQL.', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["mysql", "T1110"]', 1, 0),
(5806, 'WAZUH', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'MySQL: Multiple auth failures', 'Multiple MySQL auth failures from same source.', 'Multiples échecs MySQL depuis la même source.', 'HIGH', 85, 'BLOCK', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["mysql", "T1110.001"]', 1, 0),
(40101, 'WAZUH', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110'), 'PostgreSQL: Auth failed', 'PostgreSQL authentication failure.', 'Échec d''authentification PostgreSQL.', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["postgresql", "T1110"]', 1, 0),
(40102, 'WAZUH', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'PostgreSQL: Multiple auth failures', 'Multiple PostgreSQL auth failures.', 'Multiples échecs PostgreSQL.', 'HIGH', 85, 'BLOCK', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["postgresql", "T1110.001"]', 1, 0),
(11301, 'WAZUH', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110'), 'FTP: Multiple failed logins', 'Multiple FTP authentication failures.', 'Multiples échecs d''authentification FTP.', 'HIGH', 85, 'BLOCK', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["ftp", "T1110"]', 1, 0),
(11302, 'WAZUH', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'FTP: Brute force from same IP', 'FTP brute force attempt (insecure protocol).', 'Tentative brute force FTP (protocole non sécurisé).', 'HIGH', 90, 'BLOCK', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["ftp", "T1110.001"]', 1, 0),
(11401, 'WAZUH', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110'), 'Telnet: Failed login attempt', 'Telnet auth failure (deprecated protocol).', 'Échec d''authentification Telnet (protocole obsolète).', 'MEDIUM', 80, 'BLOCK', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["telnet", "T1110"]', 1, 0),
(9701, 'WAZUH', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110'), 'IMAP: Authentication failed', 'IMAP authentication failure.', 'Échec d''authentification IMAP.', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["imap", "T1110"]', 1, 0),
(9702, 'WAZUH', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'IMAP: Multiple auth failures', 'Multiple IMAP auth failures from same source.', 'Multiples échecs IMAP depuis la même source.', 'HIGH', 85, 'BLOCK', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["imap", "T1110.001"]', 1, 0),
(9201, 'WAZUH', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110'), 'Postfix: SASL auth failure', 'Postfix SMTP auth failure.', 'Échec auth SMTP Postfix.', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["postfix", "T1110"]', 1, 0),
(9202, 'WAZUH', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'Postfix: Multiple SASL failures', 'Multiple Postfix SMTP auth failures.', 'Multiples échecs SMTP Postfix.', 'HIGH', 85, 'BLOCK', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["postfix", "T1110.001"]', 1, 0),
(31509, 'WAZUH', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110'), 'CMS: Login attempt (WP/Joomla)', 'WordPress/Joomla login attempt.', 'Tentative connexion WordPress/Joomla.', 'INFO', 60, 'MONITOR', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["cms", "T1110"]', 1, 1),
(31510, 'WAZUH', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110'), 'CMS: Brute force attempt', '8+ login attempts in 30s on wp-login.php.', '8+ tentatives en 30s sur wp-login.php.', 'HIGH', 90, 'BLOCK', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["cms", "T1110"]', 1, 0),
(31108, 'WAZUH', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595'), 'Web: Suspicious URL access', 'Access to suspicious URL pattern (admin paths).', 'Accès à URL suspecte (chemins admin).', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["web", "T1595"]', 1, 0),
(31151, 'WAZUH', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595'), 'Web: Common attack pattern in URL', 'Common attack patterns in URL parameters.', 'Patterns d''attaque courants dans paramètres URL.', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["web", "T1595"]', 1, 0),
(31508, 'WAZUH', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595.001'), 'Web: Blacklisted user agent', 'Known malicious user agent (ZmEu, Nikto, w3af).', 'User agent malveillant (ZmEu, Nikto, w3af).', 'MEDIUM', 90, 'BLOCK', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["web", "T1595.001"]', 1, 0),
(40113, 'WAZUH', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595.001'), 'Network: Port scan detected', 'Port scan pattern detected from external source.', 'Pattern de scan de ports détecté.', 'MEDIUM', 80, 'ALERT', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["network", "T1595.001"]', 1, 0),
(40121, 'WAZUH', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595.001'), 'Network: Internal scan detected', 'Internal port scan from compromised host.', 'Scan interne depuis machine compromise.', 'HIGH', 85, 'BLOCK', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["network", "T1595.001"]', 1, 0),
(31103, 'WAZUH', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'Web: SQL injection attempt', 'SQL injection pattern in HTTP request (UNION, DROP, etc.).', 'Pattern d''injection SQL dans requête HTTP.', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["web", "T1190"]', 1, 0),
(31104, 'WAZUH', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'Web: XSS attempt', 'Cross-site scripting pattern detected.', 'Pattern XSS détecté.', 'HIGH', 85, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["web", "T1190"]', 1, 0),
(31105, 'WAZUH', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1059'), 'Web: Command injection attempt', 'Command injection pattern (; | && in URL).', 'Pattern d''injection de commande (; | && dans URL).', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["web", "T1059"]', 1, 0),
(31106, 'WAZUH', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'Web: Directory traversal', 'Path traversal attempt (../, ..%2f).', 'Tentative directory traversal (../, ..%2f).', 'HIGH', 85, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["web", "T1190"]', 1, 0),
(31107, 'WAZUH', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'Web: Local file inclusion', 'LFI attempt detected (/etc/passwd, /proc).', 'Tentative LFI détectée (/etc/passwd, /proc).', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["web", "T1190"]', 1, 0),
(31109, 'WAZUH', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'Web: Remote file inclusion', 'RFI attempt (external URL inclusion).', 'Tentative RFI (inclusion URL externe).', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["web", "T1190"]', 1, 0),
(31110, 'WAZUH', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'Web: PHP code injection', 'PHP code injection attempt.', 'Tentative injection code PHP.', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["web", "T1190"]', 1, 0),
(31111, 'WAZUH', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1059'), 'Web: Eval/exec function abuse', 'eval() or exec() function in HTTP parameters.', 'Fonction eval()/exec() dans paramètres HTTP.', 'HIGH', 85, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["web", "T1059"]', 1, 0),
(31112, 'WAZUH', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'Web: HTTP parameter pollution', 'HTTP parameter pollution attack.', 'Attaque HTTP parameter pollution.', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["web", "T1190"]', 1, 0),
(31115, 'WAZUH', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'Web: Header injection (CRLF)', 'CRLF injection in HTTP headers.', 'Injection CRLF dans en-têtes HTTP.', 'HIGH', 85, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["web", "T1190"]', 1, 0),
(31120, 'WAZUH', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'Web: Suspicious POST request', 'POST request with suspicious payload.', 'Requête POST avec payload suspect.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["web", "T1190"]', 1, 0),
(31125, 'WAZUH', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'Web: Webshell upload attempt', 'Possible webshell upload (PHP, JSP, ASPX in upload).', 'Possible upload webshell (PHP, JSP, ASPX).', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["web", "T1190"]', 1, 0),
(31130, 'WAZUH', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'Web: Server-side request forgery', 'SSRF attempt (internal URL access).', 'Tentative SSRF (accès URL interne).', 'HIGH', 85, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["web", "T1190"]', 1, 0),
(31135, 'WAZUH', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'Web: XXE attack attempt', 'XML external entity attack.', 'Attaque XML external entity.', 'HIGH', 85, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["web", "T1190"]', 1, 0),
(31140, 'WAZUH', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'Web: Deserialization attack', 'Insecure deserialization attempt.', 'Tentative deserialization non sécurisée.', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["web", "T1190"]', 1, 0),
(31145, 'WAZUH', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'Web: SSTI attack (template injection)', 'Server-side template injection attempt.', 'Tentative server-side template injection.', 'HIGH', 85, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["web", "T1190"]', 1, 0),
(31150, 'WAZUH', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'Web: NoSQL injection', 'NoSQL injection pattern in MongoDB queries.', 'Pattern injection NoSQL dans requêtes MongoDB.', 'HIGH', 85, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["web", "T1190"]', 1, 0),
(31152, 'WAZUH', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'Web: HTTP request smuggling', 'HTTP request smuggling attempt.', 'Tentative HTTP request smuggling.', 'HIGH', 85, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["web", "T1190"]', 1, 0),
(31153, 'WAZUH', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'Web: Open redirect attempt', 'Open redirect vulnerability exploitation.', 'Exploitation vulnérabilité open redirect.', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["web", "T1190"]', 1, 0),
(31154, 'WAZUH', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'Web: HTTP method tampering', 'Suspicious HTTP method (PUT, DELETE, PATCH).', 'Méthode HTTP suspecte (PUT, DELETE, PATCH).', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["web", "T1190"]', 1, 0),
(510, 'WAZUH', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1014'), 'Rootkit detection', 'Rootkit detected by rootcheck.', 'Rootkit détecté par rootcheck.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["rootkit detection", "T1014"]', 1, 0),
(511, 'WAZUH', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1059'), 'Trojan detection', 'Trojan detected by signature.', 'Trojan détecté par signature.', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["trojan detection", "T1059"]', 1, 0),
(512, 'WAZUH', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1059'), 'Suspicious binary in /tmp', 'Suspicious executable in /tmp directory.', 'Exécutable suspect dans /tmp.', 'HIGH', 85, 'ALERT', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["suspicious binary in /tmp", "T1059"]', 1, 0),
(513, 'WAZUH', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1059'), 'Suspicious file extension', 'Suspicious file extension (.exe in Linux).', 'Extension fichier suspecte (.exe sur Linux).', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["suspicious file extension", "T1059"]', 1, 0),
(514, 'WAZUH', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1014'), 'Hidden process detected', 'Hidden process detected (rootkit indicator).', 'Processus caché détecté (indicateur rootkit).', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["hidden process detected", "T1014"]', 1, 0),
(515, 'WAZUH', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1053'), 'Suspicious cron entry', 'Suspicious cron entry detected.', 'Entrée cron suspecte détectée.', 'HIGH', 80, 'ALERT', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["suspicious cron entry", "T1053"]', 1, 0),
(550, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'Integrity checksum changed', 'File integrity checksum changed.', 'Somme de contrôle d''intégrité modifiée.', 'HIGH', 85, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["integrity checksum changed", "T1565"]', 1, 0),
(2502, 'WAZUH', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1078'), 'Login from honeypot account', 'Login attempt on honeypot account.', 'Tentative de login sur compte honeypot.', 'CRITICAL', 100, 'BLOCK', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["login from honeypot account", "T1078"]', 1, 0),
(40500, 'WAZUH', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1059'), 'ClamAV: Virus detected', 'ClamAV detected a virus.', 'ClamAV a détecté un virus.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["clamav", "T1059"]', 1, 0),
(40501, 'WAZUH', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1059'), 'ClamAV: Suspicious file', 'ClamAV flagged a suspicious file.', 'ClamAV a marqué un fichier suspect.', 'HIGH', 85, 'ALERT', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["clamav", "T1059"]', 1, 0),
(60601, 'WAZUH', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1059'), 'Sysmon: Suspicious process', 'Sysmon detected a suspicious process.', 'Sysmon a détecté un processus suspect.', 'HIGH', 80, 'ALERT', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["sysmon", "T1059"]', 1, 0),
(60602, 'WAZUH', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1055'), 'Sysmon: Process injection', 'Process injection detected.', 'Injection de processus détectée.', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["sysmon", "T1055"]', 1, 0),
(60603, 'WAZUH', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1003'), 'Sysmon: Mimikatz indicator', 'Mimikatz-like behavior detected.', 'Comportement type Mimikatz détecté.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["sysmon", "T1003"]', 1, 0),
(60604, 'WAZUH', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1059.001'), 'Sysmon: Powershell encoded command', 'Powershell with base64 encoded command.', 'Powershell avec commande base64 encodée.', 'HIGH', 85, 'ALERT', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["sysmon", "T1059.001"]', 1, 0),
(60605, 'WAZUH', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1055'), 'Sysmon: Suspicious DLL load', 'Suspicious DLL loaded into process.', 'DLL suspecte chargée dans processus.', 'HIGH', 80, 'ALERT', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["sysmon", "T1055"]', 1, 0),
(60606, 'WAZUH', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1014'), 'Sysmon: Driver loaded', 'Kernel driver loaded (potential rootkit).', 'Driver kernel chargé (rootkit potentiel).', 'HIGH', 75, 'ALERT', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["sysmon", "T1014"]', 1, 0),
(60607, 'WAZUH', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071'), 'Sysmon: Network connection by suspicious process', 'Network connection from suspicious process.', 'Connexion réseau depuis processus suspect.', 'HIGH', 80, 'ALERT', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["sysmon", "T1071"]', 1, 0),
(60608, 'WAZUH', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1055'), 'Sysmon: Process hollowing', 'Process hollowing technique detected.', 'Technique process hollowing détectée.', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["sysmon", "T1055"]', 1, 0),
(60609, 'WAZUH', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1546'), 'Sysmon: WMI persistence', 'WMI used for persistence.', 'WMI utilisé pour persistance.', 'HIGH', 85, 'ALERT', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["sysmon", "T1546"]', 1, 0),
(60610, 'WAZUH', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1003.001'), 'Sysmon: LSASS access', 'LSASS process accessed (credential dump attempt).', 'Accès au processus LSASS (tentative dump credentials).', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["sysmon", "T1003.001"]', 1, 0),
(60611, 'WAZUH', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1021.002'), 'Sysmon: Network share access', 'Suspicious network share access (lateral movement).', 'Accès partage réseau suspect (mouvement latéral).', 'HIGH', 75, 'ALERT', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["sysmon", "T1021.002"]', 1, 0),
(80101, 'WAZUH', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1059'), 'Audit: Suspicious binary execution', 'Audit detected suspicious binary execution.', 'Audit a détecté exécution binaire suspecte.', 'HIGH', 80, 'ALERT', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["audit", "T1059"]', 1, 0),
(80102, 'WAZUH', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1059.004'), 'Audit: Reverse shell pattern', 'Reverse shell pattern detected (bash -i, nc -e).', 'Pattern reverse shell détecté (bash -i, nc -e).', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["audit", "T1059.004"]', 1, 0),
(80103, 'WAZUH', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1059'), 'Audit: Anonymous binary execution', 'Execution of binary in /dev/shm or /tmp.', 'Exécution binaire dans /dev/shm ou /tmp.', 'HIGH', 85, 'ALERT', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["audit", "T1059"]', 1, 0),
(80104, 'WAZUH', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1105'), 'Audit: Curl/wget to suspicious domain', 'Download from suspicious domain.', 'Téléchargement depuis domaine suspect.', 'HIGH', 80, 'ALERT', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["audit", "T1105"]', 1, 0),
(80105, 'WAZUH', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1496'), 'Audit: Crypto miner indicator', 'Cryptocurrency miner pattern detected.', 'Pattern miner cryptomonnaie détecté.', 'HIGH', 85, 'BLOCK', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["audit", "T1496"]', 1, 0),
(80106, 'WAZUH', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1548.001'), 'Audit: SUID binary execution', 'Unusual SUID binary execution.', 'Exécution binaire SUID inhabituelle.', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["audit", "T1548.001"]', 1, 0),
(80107, 'WAZUH', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1548'), 'Audit: Capabilities abuse', 'Linux capabilities abuse detected.', 'Abus de capabilities Linux détecté.', 'HIGH', 80, 'ALERT', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["audit", "T1548"]', 1, 0),
(80108, 'WAZUH', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1574'), 'Audit: LD_PRELOAD abuse', 'LD_PRELOAD environment variable abuse.', 'Abus variable d''environnement LD_PRELOAD.', 'HIGH', 85, 'ALERT', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["audit", "T1574"]', 1, 0),
(80109, 'WAZUH', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1070.003'), 'Audit: Bash history clearing', 'Bash history file cleared (anti-forensics).', 'Historique bash effacé (anti-forensics).', 'HIGH', 85, 'ALERT', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["audit", "T1070.003"]', 1, 0),
(100100, 'WAZUH', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1486'), 'Ransomware: Mass file encryption', '50+ files modified in 1 minute (encryption pattern).', '50+ fichiers modifiés en 1 minute (pattern chiffrement).', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• ⚠ URGENCE : isoler la machine immédiatement.
• DÉBRANCHER le câble réseau.
• Ne PAS payer la rançon.

À vérifier :
• Étendue de la compromission (autres machines ?).
• Existence de sauvegardes intactes.
• Identifier la variante de ransomware (notes laissées).

À corriger :
• Restauration depuis sauvegarde HORS-LIGNE.
• Réinstallation système complète.
• Forensics pour comprendre le vecteur d''entrée.
• Notification ANTIC/ARTCI dans 72h si données perso.', '["ransomware", "T1486"]', 1, 0),
(100101, 'WAZUH', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1486'), 'Ransomware: Suspicious file extension', 'Files renamed with .locked, .crypto, .encrypted extensions.', 'Fichiers renommés avec .locked, .crypto, .encrypted.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• ⚠ URGENCE : isoler la machine immédiatement.
• DÉBRANCHER le câble réseau.
• Ne PAS payer la rançon.

À vérifier :
• Étendue de la compromission (autres machines ?).
• Existence de sauvegardes intactes.
• Identifier la variante de ransomware (notes laissées).

À corriger :
• Restauration depuis sauvegarde HORS-LIGNE.
• Réinstallation système complète.
• Forensics pour comprendre le vecteur d''entrée.
• Notification ANTIC/ARTCI dans 72h si données perso.', '["ransomware", "T1486"]', 1, 0),
(100102, 'WAZUH', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1486'), 'Ransomware: Ransom note created', 'README_DECRYPT or HOW_TO_DECRYPT files created.', 'Fichiers README_DECRYPT ou HOW_TO_DECRYPT créés.', 'CRITICAL', 100, 'BLOCK', 'Action immédiate :
• ⚠ URGENCE : isoler la machine immédiatement.
• DÉBRANCHER le câble réseau.
• Ne PAS payer la rançon.

À vérifier :
• Étendue de la compromission (autres machines ?).
• Existence de sauvegardes intactes.
• Identifier la variante de ransomware (notes laissées).

À corriger :
• Restauration depuis sauvegarde HORS-LIGNE.
• Réinstallation système complète.
• Forensics pour comprendre le vecteur d''entrée.
• Notification ANTIC/ARTCI dans 72h si données perso.', '["ransomware", "T1486"]', 1, 0),
(100103, 'WAZUH', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1490'), 'Ransomware: Shadow copies deleted', 'Volume Shadow Copies deleted (vssadmin delete).', 'Volume Shadow Copies supprimés (vssadmin delete).', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• ⚠ URGENCE : isoler la machine immédiatement.
• DÉBRANCHER le câble réseau.
• Ne PAS payer la rançon.

À vérifier :
• Étendue de la compromission (autres machines ?).
• Existence de sauvegardes intactes.
• Identifier la variante de ransomware (notes laissées).

À corriger :
• Restauration depuis sauvegarde HORS-LIGNE.
• Réinstallation système complète.
• Forensics pour comprendre le vecteur d''entrée.
• Notification ANTIC/ARTCI dans 72h si données perso.', '["ransomware", "T1490"]', 1, 0),
(100104, 'WAZUH', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1490'), 'Ransomware: Backup deletion', 'Backup files deletion detected.', 'Suppression de fichiers de backup détectée.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• ⚠ URGENCE : isoler la machine immédiatement.
• DÉBRANCHER le câble réseau.
• Ne PAS payer la rançon.

À vérifier :
• Étendue de la compromission (autres machines ?).
• Existence de sauvegardes intactes.
• Identifier la variante de ransomware (notes laissées).

À corriger :
• Restauration depuis sauvegarde HORS-LIGNE.
• Réinstallation système complète.
• Forensics pour comprendre le vecteur d''entrée.
• Notification ANTIC/ARTCI dans 72h si données perso.', '["ransomware", "T1490"]', 1, 0),
(100105, 'WAZUH', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1486'), 'Ransomware: Crypto API usage', 'Suspicious cryptographic API calls.', 'Appels API cryptographique suspects.', 'HIGH', 80, 'ALERT', 'Action immédiate :
• ⚠ URGENCE : isoler la machine immédiatement.
• DÉBRANCHER le câble réseau.
• Ne PAS payer la rançon.

À vérifier :
• Étendue de la compromission (autres machines ?).
• Existence de sauvegardes intactes.
• Identifier la variante de ransomware (notes laissées).

À corriger :
• Restauration depuis sauvegarde HORS-LIGNE.
• Réinstallation système complète.
• Forensics pour comprendre le vecteur d''entrée.
• Notification ANTIC/ARTCI dans 72h si données perso.', '["ransomware", "T1486"]', 1, 0),
(100106, 'WAZUH', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1486'), 'Ransomware: Wallpaper change', 'Desktop wallpaper changed (ransomware indicator).', 'Fond d''écran changé (indicateur ransomware).', 'HIGH', 85, 'ALERT', 'Action immédiate :
• ⚠ URGENCE : isoler la machine immédiatement.
• DÉBRANCHER le câble réseau.
• Ne PAS payer la rançon.

À vérifier :
• Étendue de la compromission (autres machines ?).
• Existence de sauvegardes intactes.
• Identifier la variante de ransomware (notes laissées).

À corriger :
• Restauration depuis sauvegarde HORS-LIGNE.
• Réinstallation système complète.
• Forensics pour comprendre le vecteur d''entrée.
• Notification ANTIC/ARTCI dans 72h si données perso.', '["ransomware", "T1486"]', 1, 0),
(100107, 'WAZUH', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1486'), 'Ransomware: WMI mass execution', 'WMI used for mass remote execution.', 'WMI utilisé pour exécution distante massive.', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• ⚠ URGENCE : isoler la machine immédiatement.
• DÉBRANCHER le câble réseau.
• Ne PAS payer la rançon.

À vérifier :
• Étendue de la compromission (autres machines ?).
• Existence de sauvegardes intactes.
• Identifier la variante de ransomware (notes laissées).

À corriger :
• Restauration depuis sauvegarde HORS-LIGNE.
• Réinstallation système complète.
• Forensics pour comprendre le vecteur d''entrée.
• Notification ANTIC/ARTCI dans 72h si données perso.', '["ransomware", "T1486"]', 1, 0),
(100108, 'WAZUH', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1486'), 'Ransomware: Phobos indicator', 'Phobos ransomware behavior pattern detected.', 'Pattern comportement ransomware Phobos détecté.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• ⚠ URGENCE : isoler la machine immédiatement.
• DÉBRANCHER le câble réseau.
• Ne PAS payer la rançon.

À vérifier :
• Étendue de la compromission (autres machines ?).
• Existence de sauvegardes intactes.
• Identifier la variante de ransomware (notes laissées).

À corriger :
• Restauration depuis sauvegarde HORS-LIGNE.
• Réinstallation système complète.
• Forensics pour comprendre le vecteur d''entrée.
• Notification ANTIC/ARTCI dans 72h si données perso.', '["ransomware", "T1486"]', 1, 0),
(100109, 'WAZUH', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1486'), 'Ransomware: Dharma indicator', 'Dharma ransomware behavior pattern detected.', 'Pattern comportement ransomware Dharma détecté.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• ⚠ URGENCE : isoler la machine immédiatement.
• DÉBRANCHER le câble réseau.
• Ne PAS payer la rançon.

À vérifier :
• Étendue de la compromission (autres machines ?).
• Existence de sauvegardes intactes.
• Identifier la variante de ransomware (notes laissées).

À corriger :
• Restauration depuis sauvegarde HORS-LIGNE.
• Réinstallation système complète.
• Forensics pour comprendre le vecteur d''entrée.
• Notification ANTIC/ARTCI dans 72h si données perso.', '["ransomware", "T1486"]', 1, 0),
(100110, 'WAZUH', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1486'), 'Ransomware: LockBit indicator', 'LockBit ransomware behavior detected.', 'Comportement ransomware LockBit détecté.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• ⚠ URGENCE : isoler la machine immédiatement.
• DÉBRANCHER le câble réseau.
• Ne PAS payer la rançon.

À vérifier :
• Étendue de la compromission (autres machines ?).
• Existence de sauvegardes intactes.
• Identifier la variante de ransomware (notes laissées).

À corriger :
• Restauration depuis sauvegarde HORS-LIGNE.
• Réinstallation système complète.
• Forensics pour comprendre le vecteur d''entrée.
• Notification ANTIC/ARTCI dans 72h si données perso.', '["ransomware", "T1486"]', 1, 0),
(100111, 'WAZUH', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1486'), 'Ransomware: Ryuk indicator', 'Ryuk ransomware behavior detected.', 'Comportement ransomware Ryuk détecté.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• ⚠ URGENCE : isoler la machine immédiatement.
• DÉBRANCHER le câble réseau.
• Ne PAS payer la rançon.

À vérifier :
• Étendue de la compromission (autres machines ?).
• Existence de sauvegardes intactes.
• Identifier la variante de ransomware (notes laissées).

À corriger :
• Restauration depuis sauvegarde HORS-LIGNE.
• Réinstallation système complète.
• Forensics pour comprendre le vecteur d''entrée.
• Notification ANTIC/ARTCI dans 72h si données perso.', '["ransomware", "T1486"]', 1, 0),
(100112, 'WAZUH', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1486'), 'Ransomware: REvil indicator', 'REvil/Sodinokibi ransomware behavior detected.', 'Comportement ransomware REvil/Sodinokibi détecté.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• ⚠ URGENCE : isoler la machine immédiatement.
• DÉBRANCHER le câble réseau.
• Ne PAS payer la rançon.

À vérifier :
• Étendue de la compromission (autres machines ?).
• Existence de sauvegardes intactes.
• Identifier la variante de ransomware (notes laissées).

À corriger :
• Restauration depuis sauvegarde HORS-LIGNE.
• Réinstallation système complète.
• Forensics pour comprendre le vecteur d''entrée.
• Notification ANTIC/ARTCI dans 72h si données perso.', '["ransomware", "T1486"]', 1, 0),
(100113, 'WAZUH', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1486'), 'Ransomware: Conti indicator', 'Conti ransomware behavior detected.', 'Comportement ransomware Conti détecté.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• ⚠ URGENCE : isoler la machine immédiatement.
• DÉBRANCHER le câble réseau.
• Ne PAS payer la rançon.

À vérifier :
• Étendue de la compromission (autres machines ?).
• Existence de sauvegardes intactes.
• Identifier la variante de ransomware (notes laissées).

À corriger :
• Restauration depuis sauvegarde HORS-LIGNE.
• Réinstallation système complète.
• Forensics pour comprendre le vecteur d''entrée.
• Notification ANTIC/ARTCI dans 72h si données perso.', '["ransomware", "T1486"]', 1, 0),
(100114, 'WAZUH', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1486'), 'Ransomware: BlackCat indicator', 'BlackCat/ALPHV ransomware behavior detected.', 'Comportement ransomware BlackCat/ALPHV détecté.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• ⚠ URGENCE : isoler la machine immédiatement.
• DÉBRANCHER le câble réseau.
• Ne PAS payer la rançon.

À vérifier :
• Étendue de la compromission (autres machines ?).
• Existence de sauvegardes intactes.
• Identifier la variante de ransomware (notes laissées).

À corriger :
• Restauration depuis sauvegarde HORS-LIGNE.
• Réinstallation système complète.
• Forensics pour comprendre le vecteur d''entrée.
• Notification ANTIC/ARTCI dans 72h si données perso.', '["ransomware", "T1486"]', 1, 0),
(100115, 'WAZUH', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1486'), 'Ransomware: Akira indicator', 'Akira ransomware behavior detected.', 'Comportement ransomware Akira détecté.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• ⚠ URGENCE : isoler la machine immédiatement.
• DÉBRANCHER le câble réseau.
• Ne PAS payer la rançon.

À vérifier :
• Étendue de la compromission (autres machines ?).
• Existence de sauvegardes intactes.
• Identifier la variante de ransomware (notes laissées).

À corriger :
• Restauration depuis sauvegarde HORS-LIGNE.
• Réinstallation système complète.
• Forensics pour comprendre le vecteur d''entrée.
• Notification ANTIC/ARTCI dans 72h si données perso.', '["ransomware", "T1486"]', 1, 0),
(100116, 'WAZUH', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1486'), 'Ransomware: BitLocker abuse', 'BitLocker abused for malicious encryption.', 'BitLocker abusé pour chiffrement malveillant.', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• ⚠ URGENCE : isoler la machine immédiatement.
• DÉBRANCHER le câble réseau.
• Ne PAS payer la rançon.

À vérifier :
• Étendue de la compromission (autres machines ?).
• Existence de sauvegardes intactes.
• Identifier la variante de ransomware (notes laissées).

À corriger :
• Restauration depuis sauvegarde HORS-LIGNE.
• Réinstallation système complète.
• Forensics pour comprendre le vecteur d''entrée.
• Notification ANTIC/ARTCI dans 72h si données perso.', '["ransomware", "T1486"]', 1, 0),
(100117, 'WAZUH', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1569'), 'Ransomware: PsExec mass execution', 'PsExec used for mass execution (ransomware deployment).', 'PsExec utilisé pour exécution massive (déploiement ransomware).', 'HIGH', 85, 'BLOCK', 'Action immédiate :
• ⚠ URGENCE : isoler la machine immédiatement.
• DÉBRANCHER le câble réseau.
• Ne PAS payer la rançon.

À vérifier :
• Étendue de la compromission (autres machines ?).
• Existence de sauvegardes intactes.
• Identifier la variante de ransomware (notes laissées).

À corriger :
• Restauration depuis sauvegarde HORS-LIGNE.
• Réinstallation système complète.
• Forensics pour comprendre le vecteur d''entrée.
• Notification ANTIC/ARTCI dans 72h si données perso.', '["ransomware", "T1569"]', 1, 0),
(100118, 'WAZUH', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1484'), 'Ransomware: GPO deployment', 'Mass deployment via GPO detected.', 'Déploiement massif via GPO détecté.', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• ⚠ URGENCE : isoler la machine immédiatement.
• DÉBRANCHER le câble réseau.
• Ne PAS payer la rançon.

À vérifier :
• Étendue de la compromission (autres machines ?).
• Existence de sauvegardes intactes.
• Identifier la variante de ransomware (notes laissées).

À corriger :
• Restauration depuis sauvegarde HORS-LIGNE.
• Réinstallation système complète.
• Forensics pour comprendre le vecteur d''entrée.
• Notification ANTIC/ARTCI dans 72h si données perso.', '["ransomware", "T1484"]', 1, 0),
(100119, 'WAZUH', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1562'), 'Ransomware: Defender disabled', 'Windows Defender disabled (ransomware preparation).', 'Windows Defender désactivé (préparation ransomware).', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• ⚠ URGENCE : isoler la machine immédiatement.
• DÉBRANCHER le câble réseau.
• Ne PAS payer la rançon.

À vérifier :
• Étendue de la compromission (autres machines ?).
• Existence de sauvegardes intactes.
• Identifier la variante de ransomware (notes laissées).

À corriger :
• Restauration depuis sauvegarde HORS-LIGNE.
• Réinstallation système complète.
• Forensics pour comprendre le vecteur d''entrée.
• Notification ANTIC/ARTCI dans 72h si données perso.', '["ransomware", "T1562"]', 1, 0),
(100120, 'WAZUH', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1485'), 'Ransomware: Recycle Bin emptied', 'Recycle Bin force emptied programmatically.', 'Corbeille vidée par programme.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• ⚠ URGENCE : isoler la machine immédiatement.
• DÉBRANCHER le câble réseau.
• Ne PAS payer la rançon.

À vérifier :
• Étendue de la compromission (autres machines ?).
• Existence de sauvegardes intactes.
• Identifier la variante de ransomware (notes laissées).

À corriger :
• Restauration depuis sauvegarde HORS-LIGNE.
• Réinstallation système complète.
• Forensics pour comprendre le vecteur d''entrée.
• Notification ANTIC/ARTCI dans 72h si données perso.', '["ransomware", "T1485"]', 1, 0),
(100121, 'WAZUH', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1490'), 'Ransomware: System restore disabled', 'System Restore points deletion detected.', 'Suppression points de restauration système détectée.', 'HIGH', 85, 'BLOCK', 'Action immédiate :
• ⚠ URGENCE : isoler la machine immédiatement.
• DÉBRANCHER le câble réseau.
• Ne PAS payer la rançon.

À vérifier :
• Étendue de la compromission (autres machines ?).
• Existence de sauvegardes intactes.
• Identifier la variante de ransomware (notes laissées).

À corriger :
• Restauration depuis sauvegarde HORS-LIGNE.
• Réinstallation système complète.
• Forensics pour comprendre le vecteur d''entrée.
• Notification ANTIC/ARTCI dans 72h si données perso.', '["ransomware", "T1490"]', 1, 0),
(100122, 'WAZUH', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1542'), 'Ransomware: Boot loader modification', 'MBR/BootLoader modification (wiper).', 'Modification MBR/BootLoader (wiper).', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• ⚠ URGENCE : isoler la machine immédiatement.
• DÉBRANCHER le câble réseau.
• Ne PAS payer la rançon.

À vérifier :
• Étendue de la compromission (autres machines ?).
• Existence de sauvegardes intactes.
• Identifier la variante de ransomware (notes laissées).

À corriger :
• Restauration depuis sauvegarde HORS-LIGNE.
• Réinstallation système complète.
• Forensics pour comprendre le vecteur d''entrée.
• Notification ANTIC/ARTCI dans 72h si données perso.', '["ransomware", "T1542"]', 1, 0),
(100123, 'WAZUH', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1486'), 'Ransomware: Mass network share encryption', 'Mass encryption on network shares.', 'Chiffrement massif sur partages réseau.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• ⚠ URGENCE : isoler la machine immédiatement.
• DÉBRANCHER le câble réseau.
• Ne PAS payer la rançon.

À vérifier :
• Étendue de la compromission (autres machines ?).
• Existence de sauvegardes intactes.
• Identifier la variante de ransomware (notes laissées).

À corriger :
• Restauration depuis sauvegarde HORS-LIGNE.
• Réinstallation système complète.
• Forensics pour comprendre le vecteur d''entrée.
• Notification ANTIC/ARTCI dans 72h si données perso.', '["ransomware", "T1486"]', 1, 0),
(100124, 'WAZUH', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1490'), 'Ransomware: Backup software disabled', 'Backup software service stopped maliciously.', 'Service logiciel de backup arrêté malicieusement.', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• ⚠ URGENCE : isoler la machine immédiatement.
• DÉBRANCHER le câble réseau.
• Ne PAS payer la rançon.

À vérifier :
• Étendue de la compromission (autres machines ?).
• Existence de sauvegardes intactes.
• Identifier la variante de ransomware (notes laissées).

À corriger :
• Restauration depuis sauvegarde HORS-LIGNE.
• Réinstallation système complète.
• Forensics pour comprendre le vecteur d''entrée.
• Notification ANTIC/ARTCI dans 72h si données perso.', '["ransomware", "T1490"]', 1, 0),
(553, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: File added', 'New file detected in monitored directory.', 'Nouveau fichier détecté dans répertoire surveillé.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(554, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1485'), 'FIM: File deleted', 'File deleted from monitored directory.', 'Fichier supprimé du répertoire surveillé.', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1485"]', 1, 0),
(594, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Sensitive file modified', 'Sensitive system file modified.', 'Fichier système sensible modifié.', 'HIGH', 85, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(597, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1564'), 'FIM: Hidden file detected', 'Hidden file in suspicious location.', 'Fichier caché dans emplacement suspect.', 'HIGH', 80, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1564"]', 1, 0),
(100200, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100200', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100201, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100201', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100202, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100202', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100203, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100203', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100204, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100204', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100205, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100205', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100206, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100206', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100207, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100207', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100208, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100208', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100209, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100209', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100210, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100210', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100211, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100211', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100212, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100212', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100213, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100213', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100214, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100214', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100215, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100215', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100216, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100216', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100217, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100217', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100218, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100218', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100219, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100219', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100220, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100220', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100221, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100221', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100222, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100222', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100223, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100223', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100224, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100224', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100225, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100225', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100226, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100226', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100227, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100227', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100228, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100228', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100229, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100229', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100230, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100230', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100231, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100231', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100232, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100232', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100233, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100233', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100234, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100234', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100235, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100235', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100236, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100236', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100237, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100237', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100238, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100238', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100239, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100239', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100240, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100240', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100241, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100241', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100242, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100242', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100243, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100243', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(100244, 'WAZUH', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1565'), 'FIM: Custom rule 100244', 'File integrity event from custom monitoring rule.', 'Événement d''intégrité fichier depuis règle custom.', 'MEDIUM', 70, 'ALERT', 'Action immédiate :
• Vérifier qui a modifié le fichier (audit log).
• Si modification non autorisée : alerter immédiatement.

À vérifier :
• Date/heure de modification.
• Utilisateur ayant fait la modification.
• Diff avec la version précédente.

À corriger :
• Restaurer depuis backup si modification malveillante.
• Renforcer permissions (chmod restrictif).
• Activer auditd pour traçabilité fine.', '["fim", "T1565"]', 1, 0),
(5405, 'WAZUH', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1548'), 'sudo: User not allowed', 'User attempted sudo without permission.', 'Utilisateur sans permission tente sudo.', 'HIGH', 90, 'ALERT', 'Action immédiate :
• Vérifier les commandes exécutées par cet utilisateur.
• Auditer ses connexions récentes.

À vérifier :
• Pourquoi cet utilisateur tente une élévation.
• Si action légitime (admin) ou suspecte.

À corriger :
• Réviser les permissions sudo (/etc/sudoers).
• Limiter les droits aux strict nécessaire (principe moindre privilège).
• Logger toutes commandes sudo.', '["sudo", "T1548"]', 1, 0),
(5406, 'WAZUH', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1548'), 'sudo: Command not allowed', 'User attempted forbidden sudo command.', 'Utilisateur tente commande sudo interdite.', 'HIGH', 85, 'ALERT', 'Action immédiate :
• Vérifier les commandes exécutées par cet utilisateur.
• Auditer ses connexions récentes.

À vérifier :
• Pourquoi cet utilisateur tente une élévation.
• Si action légitime (admin) ou suspecte.

À corriger :
• Réviser les permissions sudo (/etc/sudoers).
• Limiter les droits aux strict nécessaire (principe moindre privilège).
• Logger toutes commandes sudo.', '["sudo", "T1548"]', 1, 0),
(5407, 'WAZUH', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1548'), 'su: Authentication failure', 'Failed su attempt.', 'Tentative su échouée.', 'MEDIUM', 80, 'ALERT', 'Action immédiate :
• Vérifier les commandes exécutées par cet utilisateur.
• Auditer ses connexions récentes.

À vérifier :
• Pourquoi cet utilisateur tente une élévation.
• Si action légitime (admin) ou suspecte.

À corriger :
• Réviser les permissions sudo (/etc/sudoers).
• Limiter les droits aux strict nécessaire (principe moindre privilège).
• Logger toutes commandes sudo.', '["su", "T1548"]', 1, 0),
(5301, 'WAZUH', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1136'), 'New user added to system', 'New user account created.', 'Nouveau compte utilisateur créé.', 'HIGH', 85, 'ALERT', 'Action immédiate :
• Vérifier les commandes exécutées par cet utilisateur.
• Auditer ses connexions récentes.

À vérifier :
• Pourquoi cet utilisateur tente une élévation.
• Si action légitime (admin) ou suspecte.

À corriger :
• Réviser les permissions sudo (/etc/sudoers).
• Limiter les droits aux strict nécessaire (principe moindre privilège).
• Logger toutes commandes sudo.', '["new user added to system", "T1136"]', 1, 0),
(5302, 'WAZUH', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1078'), 'User added to root group', 'User added to privileged group.', 'Utilisateur ajouté à un groupe privilégié.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• Vérifier les commandes exécutées par cet utilisateur.
• Auditer ses connexions récentes.

À vérifier :
• Pourquoi cet utilisateur tente une élévation.
• Si action légitime (admin) ou suspecte.

À corriger :
• Réviser les permissions sudo (/etc/sudoers).
• Limiter les droits aux strict nécessaire (principe moindre privilège).
• Logger toutes commandes sudo.', '["user added to root group", "T1078"]', 1, 0),
(5303, 'WAZUH', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1098'), 'User account modified', 'User account properties modified.', 'Propriétés compte utilisateur modifiées.', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• Vérifier les commandes exécutées par cet utilisateur.
• Auditer ses connexions récentes.

À vérifier :
• Pourquoi cet utilisateur tente une élévation.
• Si action légitime (admin) ou suspecte.

À corriger :
• Réviser les permissions sudo (/etc/sudoers).
• Limiter les droits aux strict nécessaire (principe moindre privilège).
• Logger toutes commandes sudo.', '["user account modified", "T1098"]', 1, 0),
(5304, 'WAZUH', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1531'), 'User account deleted', 'User account deleted.', 'Compte utilisateur supprimé.', 'HIGH', 85, 'ALERT', 'Action immédiate :
• Vérifier les commandes exécutées par cet utilisateur.
• Auditer ses connexions récentes.

À vérifier :
• Pourquoi cet utilisateur tente une élévation.
• Si action légitime (admin) ou suspecte.

À corriger :
• Réviser les permissions sudo (/etc/sudoers).
• Limiter les droits aux strict nécessaire (principe moindre privilège).
• Logger toutes commandes sudo.', '["user account deleted", "T1531"]', 1, 0),
(5305, 'WAZUH', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1078'), 'Root user logged in', 'Direct root login detected.', 'Connexion root directe détectée.', 'HIGH', 80, 'ALERT', 'Action immédiate :
• Vérifier les commandes exécutées par cet utilisateur.
• Auditer ses connexions récentes.

À vérifier :
• Pourquoi cet utilisateur tente une élévation.
• Si action légitime (admin) ou suspecte.

À corriger :
• Réviser les permissions sudo (/etc/sudoers).
• Limiter les droits aux strict nécessaire (principe moindre privilège).
• Logger toutes commandes sudo.', '["root user logged in", "T1078"]', 1, 0),
(80201, 'WAZUH', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1548'), 'Privilege escalation event 80201', 'Privilege escalation pattern detected.', 'Pattern d''élévation de privilège détecté.', 'HIGH', 80, 'ALERT', 'Action immédiate :
• Vérifier les commandes exécutées par cet utilisateur.
• Auditer ses connexions récentes.

À vérifier :
• Pourquoi cet utilisateur tente une élévation.
• Si action légitime (admin) ou suspecte.

À corriger :
• Réviser les permissions sudo (/etc/sudoers).
• Limiter les droits aux strict nécessaire (principe moindre privilège).
• Logger toutes commandes sudo.', '["privilege escalation event 80201", "T1548"]', 1, 0),
(80202, 'WAZUH', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1548'), 'Privilege escalation event 80202', 'Privilege escalation pattern detected.', 'Pattern d''élévation de privilège détecté.', 'HIGH', 80, 'ALERT', 'Action immédiate :
• Vérifier les commandes exécutées par cet utilisateur.
• Auditer ses connexions récentes.

À vérifier :
• Pourquoi cet utilisateur tente une élévation.
• Si action légitime (admin) ou suspecte.

À corriger :
• Réviser les permissions sudo (/etc/sudoers).
• Limiter les droits aux strict nécessaire (principe moindre privilège).
• Logger toutes commandes sudo.', '["privilege escalation event 80202", "T1548"]', 1, 0),
(80203, 'WAZUH', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1548'), 'Privilege escalation event 80203', 'Privilege escalation pattern detected.', 'Pattern d''élévation de privilège détecté.', 'HIGH', 80, 'ALERT', 'Action immédiate :
• Vérifier les commandes exécutées par cet utilisateur.
• Auditer ses connexions récentes.

À vérifier :
• Pourquoi cet utilisateur tente une élévation.
• Si action légitime (admin) ou suspecte.

À corriger :
• Réviser les permissions sudo (/etc/sudoers).
• Limiter les droits aux strict nécessaire (principe moindre privilège).
• Logger toutes commandes sudo.', '["privilege escalation event 80203", "T1548"]', 1, 0),
(80204, 'WAZUH', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1548'), 'Privilege escalation event 80204', 'Privilege escalation pattern detected.', 'Pattern d''élévation de privilège détecté.', 'HIGH', 80, 'ALERT', 'Action immédiate :
• Vérifier les commandes exécutées par cet utilisateur.
• Auditer ses connexions récentes.

À vérifier :
• Pourquoi cet utilisateur tente une élévation.
• Si action légitime (admin) ou suspecte.

À corriger :
• Réviser les permissions sudo (/etc/sudoers).
• Limiter les droits aux strict nécessaire (principe moindre privilège).
• Logger toutes commandes sudo.', '["privilege escalation event 80204", "T1548"]', 1, 0),
(80205, 'WAZUH', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1548'), 'Privilege escalation event 80205', 'Privilege escalation pattern detected.', 'Pattern d''élévation de privilège détecté.', 'HIGH', 80, 'ALERT', 'Action immédiate :
• Vérifier les commandes exécutées par cet utilisateur.
• Auditer ses connexions récentes.

À vérifier :
• Pourquoi cet utilisateur tente une élévation.
• Si action légitime (admin) ou suspecte.

À corriger :
• Réviser les permissions sudo (/etc/sudoers).
• Limiter les droits aux strict nécessaire (principe moindre privilège).
• Logger toutes commandes sudo.', '["privilege escalation event 80205", "T1548"]', 1, 0),
(80206, 'WAZUH', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1548'), 'Privilege escalation event 80206', 'Privilege escalation pattern detected.', 'Pattern d''élévation de privilège détecté.', 'HIGH', 80, 'ALERT', 'Action immédiate :
• Vérifier les commandes exécutées par cet utilisateur.
• Auditer ses connexions récentes.

À vérifier :
• Pourquoi cet utilisateur tente une élévation.
• Si action légitime (admin) ou suspecte.

À corriger :
• Réviser les permissions sudo (/etc/sudoers).
• Limiter les droits aux strict nécessaire (principe moindre privilège).
• Logger toutes commandes sudo.', '["privilege escalation event 80206", "T1548"]', 1, 0),
(80207, 'WAZUH', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1548'), 'Privilege escalation event 80207', 'Privilege escalation pattern detected.', 'Pattern d''élévation de privilège détecté.', 'HIGH', 80, 'ALERT', 'Action immédiate :
• Vérifier les commandes exécutées par cet utilisateur.
• Auditer ses connexions récentes.

À vérifier :
• Pourquoi cet utilisateur tente une élévation.
• Si action légitime (admin) ou suspecte.

À corriger :
• Réviser les permissions sudo (/etc/sudoers).
• Limiter les droits aux strict nécessaire (principe moindre privilège).
• Logger toutes commandes sudo.', '["privilege escalation event 80207", "T1548"]', 1, 0),
(80208, 'WAZUH', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1548'), 'Privilege escalation event 80208', 'Privilege escalation pattern detected.', 'Pattern d''élévation de privilège détecté.', 'HIGH', 80, 'ALERT', 'Action immédiate :
• Vérifier les commandes exécutées par cet utilisateur.
• Auditer ses connexions récentes.

À vérifier :
• Pourquoi cet utilisateur tente une élévation.
• Si action légitime (admin) ou suspecte.

À corriger :
• Réviser les permissions sudo (/etc/sudoers).
• Limiter les droits aux strict nécessaire (principe moindre privilège).
• Logger toutes commandes sudo.', '["privilege escalation event 80208", "T1548"]', 1, 0),
(80209, 'WAZUH', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1548'), 'Privilege escalation event 80209', 'Privilege escalation pattern detected.', 'Pattern d''élévation de privilège détecté.', 'HIGH', 80, 'ALERT', 'Action immédiate :
• Vérifier les commandes exécutées par cet utilisateur.
• Auditer ses connexions récentes.

À vérifier :
• Pourquoi cet utilisateur tente une élévation.
• Si action légitime (admin) ou suspecte.

À corriger :
• Réviser les permissions sudo (/etc/sudoers).
• Limiter les droits aux strict nécessaire (principe moindre privilège).
• Logger toutes commandes sudo.', '["privilege escalation event 80209", "T1548"]', 1, 0),
(80210, 'WAZUH', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1548'), 'Privilege escalation event 80210', 'Privilege escalation pattern detected.', 'Pattern d''élévation de privilège détecté.', 'HIGH', 80, 'ALERT', 'Action immédiate :
• Vérifier les commandes exécutées par cet utilisateur.
• Auditer ses connexions récentes.

À vérifier :
• Pourquoi cet utilisateur tente une élévation.
• Si action légitime (admin) ou suspecte.

À corriger :
• Réviser les permissions sudo (/etc/sudoers).
• Limiter les droits aux strict nécessaire (principe moindre privilège).
• Logger toutes commandes sudo.', '["privilege escalation event 80210", "T1548"]', 1, 0),
(80211, 'WAZUH', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1548'), 'Privilege escalation event 80211', 'Privilege escalation pattern detected.', 'Pattern d''élévation de privilège détecté.', 'HIGH', 80, 'ALERT', 'Action immédiate :
• Vérifier les commandes exécutées par cet utilisateur.
• Auditer ses connexions récentes.

À vérifier :
• Pourquoi cet utilisateur tente une élévation.
• Si action légitime (admin) ou suspecte.

À corriger :
• Réviser les permissions sudo (/etc/sudoers).
• Limiter les droits aux strict nécessaire (principe moindre privilège).
• Logger toutes commandes sudo.', '["privilege escalation event 80211", "T1548"]', 1, 0),
(80212, 'WAZUH', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1548'), 'Privilege escalation event 80212', 'Privilege escalation pattern detected.', 'Pattern d''élévation de privilège détecté.', 'HIGH', 80, 'ALERT', 'Action immédiate :
• Vérifier les commandes exécutées par cet utilisateur.
• Auditer ses connexions récentes.

À vérifier :
• Pourquoi cet utilisateur tente une élévation.
• Si action légitime (admin) ou suspecte.

À corriger :
• Réviser les permissions sudo (/etc/sudoers).
• Limiter les droits aux strict nécessaire (principe moindre privilège).
• Logger toutes commandes sudo.', '["privilege escalation event 80212", "T1548"]', 1, 0),
(80213, 'WAZUH', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1548'), 'Privilege escalation event 80213', 'Privilege escalation pattern detected.', 'Pattern d''élévation de privilège détecté.', 'HIGH', 80, 'ALERT', 'Action immédiate :
• Vérifier les commandes exécutées par cet utilisateur.
• Auditer ses connexions récentes.

À vérifier :
• Pourquoi cet utilisateur tente une élévation.
• Si action légitime (admin) ou suspecte.

À corriger :
• Réviser les permissions sudo (/etc/sudoers).
• Limiter les droits aux strict nécessaire (principe moindre privilège).
• Logger toutes commandes sudo.', '["privilege escalation event 80213", "T1548"]', 1, 0),
(80214, 'WAZUH', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1548'), 'Privilege escalation event 80214', 'Privilege escalation pattern detected.', 'Pattern d''élévation de privilège détecté.', 'HIGH', 80, 'ALERT', 'Action immédiate :
• Vérifier les commandes exécutées par cet utilisateur.
• Auditer ses connexions récentes.

À vérifier :
• Pourquoi cet utilisateur tente une élévation.
• Si action légitime (admin) ou suspecte.

À corriger :
• Réviser les permissions sudo (/etc/sudoers).
• Limiter les droits aux strict nécessaire (principe moindre privilège).
• Logger toutes commandes sudo.', '["privilege escalation event 80214", "T1548"]', 1, 0),
(2001219, 'SNORT', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110'), 'ET POLICY: SSH connection brute force', 'SSH brute force detected at network level.', 'Brute force SSH détecté niveau réseau.', 'HIGH', 85, 'BLOCK', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["et policy", "T1110"]', 1, 0),
(2002910, 'SNORT', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595'), 'ET SCAN: Potential SSH scan', 'SSH scan from external IP.', 'Scan SSH depuis IP externe.', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["et scan", "T1595"]', 1, 0),
(2003068, 'SNORT', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595'), 'ET SCAN: Potential SSH scan OUTBOUND', 'Outbound SSH scan (compromised host).', 'Scan SSH sortant (host compromis).', 'HIGH', 85, 'BLOCK', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["et scan", "T1595"]', 1, 0),
(2010935, 'SNORT', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110'), 'ET POLICY: RDP brute force', 'RDP brute force at network level.', 'Brute force RDP niveau réseau.', 'HIGH', 85, 'BLOCK', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["et policy", "T1110"]', 1, 0),
(2102465, 'SNORT', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1078'), 'GPL TELNET access', 'Telnet access (insecure).', 'Accès Telnet (non sécurisé).', 'MEDIUM', 80, 'ALERT', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["gpl telnet access", "T1078"]', 1, 0),
(2102466, 'SNORT', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110'), 'GPL TELNET Bad Login', 'Telnet failed login attempt.', 'Tentative connexion Telnet échouée.', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["gpl telnet bad login", "T1110"]', 1, 0),
(2008985, 'SNORT', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110'), 'ET SCAN: VNC brute force', 'VNC brute force attempt.', 'Tentative brute force VNC.', 'HIGH', 85, 'BLOCK', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["et scan", "T1110"]', 1, 0),
(2009714, 'SNORT', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110'), 'ET SCAN: FTP brute force', 'FTP brute force at network level.', 'Brute force FTP niveau réseau.', 'HIGH', 85, 'BLOCK', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["et scan", "T1110"]', 1, 0),
(2009715, 'SNORT', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110'), 'ET SCAN: POP3 brute force', 'POP3 brute force attempt.', 'Tentative brute force POP3.', 'HIGH', 85, 'BLOCK', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["et scan", "T1110"]', 1, 0),
(2009716, 'SNORT', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110'), 'ET SCAN: SMTP brute force', 'SMTP brute force attempt.', 'Tentative brute force SMTP.', 'HIGH', 85, 'BLOCK', 'Action immédiate :
• L''agent SIEM va bloquer l''IP source automatiquement (1h).
• Vérifier le compte ciblé dans les logs.

À vérifier :
• Si compte privilégié ciblé : changer le mot de passe.
• Logs auth : grep "Failed" /var/log/auth.log

À corriger :
• Activer fail2ban : apt install fail2ban
• Désactiver auth par mot de passe SSH (clés uniquement).
• Activer MFA pour tous comptes privilégiés.', '["et scan", "T1110"]', 1, 0),
(2100469, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595.002'), 'GPL ICMP PING NMAP', 'Nmap ping scan detected.', 'Scan ping nmap détecté.', 'MEDIUM', 80, 'ALERT', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["gpl icmp ping nmap", "T1595.002"]', 1, 0),
(2100498, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595.001'), 'GPL SCAN nmap TCP', 'TCP scan with nmap signatures.', 'Scan TCP avec signatures nmap.', 'MEDIUM', 80, 'ALERT', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["gpl scan nmap tcp", "T1595.001"]', 1, 0),
(2100499, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595.001'), 'GPL SCAN nmap XMAS', 'Nmap XMAS scan (FIN+URG+PSH flags).', 'Scan XMAS nmap (drapeaux FIN+URG+PSH).', 'MEDIUM', 80, 'ALERT', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["gpl scan nmap xmas", "T1595.001"]', 1, 0),
(2100500, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595.001'), 'GPL SCAN nmap NULL', 'Nmap NULL scan (no flags).', 'Scan NULL nmap (pas de drapeaux).', 'MEDIUM', 80, 'ALERT', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["gpl scan nmap null", "T1595.001"]', 1, 0),
(2100501, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595.001'), 'GPL SCAN nmap FIN', 'Nmap FIN scan.', 'Scan FIN nmap.', 'MEDIUM', 80, 'ALERT', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["gpl scan nmap fin", "T1595.001"]', 1, 0),
(2100384, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595.002'), 'GPL ICMP PING speedera', 'Generic ICMP ping speedera pattern.', 'Pattern ICMP ping speedera.', 'LOW', 60, 'MONITOR', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["gpl icmp ping speedera", "T1595.002"]', 1, 0),
(2002995, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595'), 'ET SCAN Possible NMAP User-Agent', 'NMAP scripting engine user agent.', 'User agent NMAP scripting engine.', 'MEDIUM', 80, 'ALERT', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["et scan possible nmap user-agent", "T1595"]', 1, 0),
(2008984, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595.002'), 'ET SCAN Nikto Scan in Progress', 'Nikto web scanner detected.', 'Scanner web Nikto détecté.', 'MEDIUM', 90, 'BLOCK', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["et scan nikto scan in progress", "T1595.002"]', 1, 0),
(2010516, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595'), 'ET SCAN ZmEu Scanner', 'ZmEu vulnerability scanner.', 'Scanner vulnérabilité ZmEu.', 'HIGH', 95, 'BLOCK', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["et scan zmeu scanner", "T1595"]', 1, 0),
(2003628, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595'), 'ET SCAN Sipvicious User-Agent', 'SIPVicious VoIP scanner.', 'Scanner VoIP SIPVicious.', 'MEDIUM', 90, 'BLOCK', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["et scan sipvicious user-agent", "T1595"]', 1, 0),
(2002878, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595'), 'ET SCAN Suspicious User-Agent (libwww)', 'libwww-perl user agent (often malicious).', 'User agent libwww-perl (souvent malveillant).', 'LOW', 60, 'MONITOR', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["et scan suspicious user-agent (libwww)", "T1595"]', 1, 0),
(2017582, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595.001'), 'ET SCAN masscan', 'masscan scanner detected.', 'Scanner masscan détecté.', 'MEDIUM', 85, 'ALERT', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["et scan masscan", "T1595.001"]', 1, 0),
(2018471, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595'), 'ET SCAN sqlmap', 'sqlmap SQL injection scanner.', 'Scanner injection SQL sqlmap.', 'HIGH', 95, 'BLOCK', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["et scan sqlmap", "T1595"]', 1, 0),
(2014980, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595'), 'ET SCAN Acunetix', 'Acunetix web scanner.', 'Scanner web Acunetix.', 'MEDIUM', 85, 'ALERT', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["et scan acunetix", "T1595"]', 1, 0),
(2014981, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595'), 'ET SCAN Burp Suite', 'Burp Suite scanner pattern.', 'Pattern scanner Burp Suite.', 'LOW', 70, 'MONITOR', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["et scan burp suite", "T1595"]', 1, 0),
(2015531, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595'), 'ET SCAN OpenVAS', 'OpenVAS vulnerability scanner.', 'Scanner vulnérabilité OpenVAS.', 'MEDIUM', 80, 'ALERT', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["et scan openvas", "T1595"]', 1, 0),
(2016696, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595'), 'ET SCAN Nessus', 'Nessus vulnerability scanner.', 'Scanner vulnérabilité Nessus.', 'MEDIUM', 80, 'ALERT', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["et scan nessus", "T1595"]', 1, 0),
(2002911, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110'), 'ET SCAN Possible SSH brute', 'Possible SSH brute force scan.', 'Possible scan brute force SSH.', 'HIGH', 85, 'BLOCK', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["et scan possible ssh brute", "T1110"]', 1, 0),
(2100502, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595'), 'Snort SCAN signature 2100502', 'Network scanning pattern detected.', 'Pattern de scan réseau détecté.', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["snort scan signature 2100502", "T1595"]', 1, 0),
(2100503, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595'), 'Snort SCAN signature 2100503', 'Network scanning pattern detected.', 'Pattern de scan réseau détecté.', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["snort scan signature 2100503", "T1595"]', 1, 0),
(2100504, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595'), 'Snort SCAN signature 2100504', 'Network scanning pattern detected.', 'Pattern de scan réseau détecté.', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["snort scan signature 2100504", "T1595"]', 1, 0),
(2100505, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595'), 'Snort SCAN signature 2100505', 'Network scanning pattern detected.', 'Pattern de scan réseau détecté.', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["snort scan signature 2100505", "T1595"]', 1, 0),
(2100506, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595'), 'Snort SCAN signature 2100506', 'Network scanning pattern detected.', 'Pattern de scan réseau détecté.', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["snort scan signature 2100506", "T1595"]', 1, 0),
(2100507, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595'), 'Snort SCAN signature 2100507', 'Network scanning pattern detected.', 'Pattern de scan réseau détecté.', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["snort scan signature 2100507", "T1595"]', 1, 0),
(2100508, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595'), 'Snort SCAN signature 2100508', 'Network scanning pattern detected.', 'Pattern de scan réseau détecté.', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["snort scan signature 2100508", "T1595"]', 1, 0),
(2100509, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595'), 'Snort SCAN signature 2100509', 'Network scanning pattern detected.', 'Pattern de scan réseau détecté.', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["snort scan signature 2100509", "T1595"]', 1, 0),
(2100510, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595'), 'Snort SCAN signature 2100510', 'Network scanning pattern detected.', 'Pattern de scan réseau détecté.', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["snort scan signature 2100510", "T1595"]', 1, 0),
(2100511, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595'), 'Snort SCAN signature 2100511', 'Network scanning pattern detected.', 'Pattern de scan réseau détecté.', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["snort scan signature 2100511", "T1595"]', 1, 0),
(2100512, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595'), 'Snort SCAN signature 2100512', 'Network scanning pattern detected.', 'Pattern de scan réseau détecté.', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["snort scan signature 2100512", "T1595"]', 1, 0),
(2100513, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595'), 'Snort SCAN signature 2100513', 'Network scanning pattern detected.', 'Pattern de scan réseau détecté.', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["snort scan signature 2100513", "T1595"]', 1, 0),
(2100514, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595'), 'Snort SCAN signature 2100514', 'Network scanning pattern detected.', 'Pattern de scan réseau détecté.', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["snort scan signature 2100514", "T1595"]', 1, 0),
(2100515, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595'), 'Snort SCAN signature 2100515', 'Network scanning pattern detected.', 'Pattern de scan réseau détecté.', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["snort scan signature 2100515", "T1595"]', 1, 0),
(2100516, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595'), 'Snort SCAN signature 2100516', 'Network scanning pattern detected.', 'Pattern de scan réseau détecté.', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["snort scan signature 2100516", "T1595"]', 1, 0),
(2100517, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595'), 'Snort SCAN signature 2100517', 'Network scanning pattern detected.', 'Pattern de scan réseau détecté.', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["snort scan signature 2100517", "T1595"]', 1, 0),
(2100518, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595'), 'Snort SCAN signature 2100518', 'Network scanning pattern detected.', 'Pattern de scan réseau détecté.', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["snort scan signature 2100518", "T1595"]', 1, 0),
(2100519, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595'), 'Snort SCAN signature 2100519', 'Network scanning pattern detected.', 'Pattern de scan réseau détecté.', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["snort scan signature 2100519", "T1595"]', 1, 0),
(2100520, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595'), 'Snort SCAN signature 2100520', 'Network scanning pattern detected.', 'Pattern de scan réseau détecté.', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["snort scan signature 2100520", "T1595"]', 1, 0),
(2100521, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595'), 'Snort SCAN signature 2100521', 'Network scanning pattern detected.', 'Pattern de scan réseau détecté.', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["snort scan signature 2100521", "T1595"]', 1, 0),
(2100522, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595'), 'Snort SCAN signature 2100522', 'Network scanning pattern detected.', 'Pattern de scan réseau détecté.', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["snort scan signature 2100522", "T1595"]', 1, 0),
(2100523, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595'), 'Snort SCAN signature 2100523', 'Network scanning pattern detected.', 'Pattern de scan réseau détecté.', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["snort scan signature 2100523", "T1595"]', 1, 0),
(2100524, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595'), 'Snort SCAN signature 2100524', 'Network scanning pattern detected.', 'Pattern de scan réseau détecté.', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["snort scan signature 2100524", "T1595"]', 1, 0),
(2100525, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595'), 'Snort SCAN signature 2100525', 'Network scanning pattern detected.', 'Pattern de scan réseau détecté.', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["snort scan signature 2100525", "T1595"]', 1, 0),
(2100526, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595'), 'Snort SCAN signature 2100526', 'Network scanning pattern detected.', 'Pattern de scan réseau détecté.', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["snort scan signature 2100526", "T1595"]', 1, 0),
(2100527, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595'), 'Snort SCAN signature 2100527', 'Network scanning pattern detected.', 'Pattern de scan réseau détecté.', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["snort scan signature 2100527", "T1595"]', 1, 0),
(2100528, 'SNORT', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1595'), 'Snort SCAN signature 2100528', 'Network scanning pattern detected.', 'Pattern de scan réseau détecté.', 'MEDIUM', 75, 'ALERT', 'Action immédiate :
• Logger l''IP dans threat_intel (surveillance 24h).
• Si IP externe non whitelistée : bloquer 4h.

À vérifier :
• Cette IP est-elle un scanner légitime (Shodan, Censys, audit) ?
• Inventaire des ports exposés : nmap localhost

À corriger :
• Fermer les ports non nécessaires (iptables/firewall cloud).
• Vérifier que les services exposés sont à jour.', '["snort scan signature 2100528", "T1595"]', 1, 0),
(2017919, 'SNORT', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'ET WEB SQL Injection Attempt', 'Generic SQL injection pattern.', 'Pattern injection SQL générique.', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["et web sql injection attempt", "T1190"]', 1, 0),
(2010493, 'SNORT', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'ET WEB UNION SELECT detected', 'UNION SELECT in HTTP request.', 'UNION SELECT dans requête HTTP.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["et web union select detected", "T1190"]', 1, 0),
(2008581, 'SNORT', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'ET WEB DROP TABLE detected', 'DROP TABLE in HTTP request.', 'DROP TABLE dans requête HTTP.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["et web drop table detected", "T1190"]', 1, 0),
(2009230, 'SNORT', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'ET WEB OR 1=1 SQL injection', 'Classic OR 1=1 SQL injection.', 'Injection SQL classique OR 1=1.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["et web or 1=1 sql injection", "T1190"]', 1, 0),
(2010175, 'SNORT', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'ET WEB XSS script tag', '<script> tag in HTTP parameter.', 'Tag <script> dans paramètre HTTP.', 'HIGH', 90, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["et web xss script tag", "T1190"]', 1, 0),
(2014915, 'SNORT', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'ET WEB onerror= XSS', 'XSS via onerror event.', 'XSS via événement onerror.', 'HIGH', 85, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["et web onerror= xss", "T1190"]', 1, 0),
(2010701, 'SNORT', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'ET WEB javascript: protocol XSS', 'javascript: protocol in URL.', 'Protocole javascript: dans URL.', 'HIGH', 85, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["et web javascript", "T1190"]', 1, 0),
(2009148, 'SNORT', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'ET WEB Directory Traversal', 'Path traversal ../../../', 'Directory traversal ../../../', 'HIGH', 90, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["et web directory traversal", "T1190"]', 1, 0),
(2010142, 'SNORT', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'ET WEB ../etc/passwd attempt', 'Attempt to access /etc/passwd.', 'Tentative accès /etc/passwd.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["et web ../etc/passwd attempt", "T1190"]', 1, 0),
(2010143, 'SNORT', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'ET WEB ../etc/shadow attempt', 'Attempt to access /etc/shadow.', 'Tentative accès /etc/shadow.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["et web ../etc/shadow attempt", "T1190"]', 1, 0),
(2010144, 'SNORT', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'ET WEB ../proc/self/environ', 'Attempt to access /proc/self/environ.', 'Tentative accès /proc/self/environ.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["et web ../proc/self/environ", "T1190"]', 1, 0),
(2010145, 'SNORT', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'ET WEB PHP Code Injection', 'PHP code in HTTP parameter.', 'Code PHP dans paramètre HTTP.', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["et web php code injection", "T1190"]', 1, 0),
(2010146, 'SNORT', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'ET WEB phpinfo() detected', 'phpinfo() function call attempt.', 'Tentative appel phpinfo().', 'HIGH', 85, 'ALERT', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["et web phpinfo() detected", "T1190"]', 1, 0),
(2010147, 'SNORT', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1059'), 'ET WEB system() function', 'system() function in HTTP.', 'Fonction system() dans HTTP.', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["et web system() function", "T1059"]', 1, 0),
(2010148, 'SNORT', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1059'), 'ET WEB exec() function', 'exec() function in HTTP.', 'Fonction exec() dans HTTP.', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["et web exec() function", "T1059"]', 1, 0),
(2010149, 'SNORT', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1059'), 'ET WEB passthru() function', 'passthru() function in HTTP.', 'Fonction passthru() dans HTTP.', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["et web passthru() function", "T1059"]', 1, 0),
(2010150, 'SNORT', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'ET WEB base64_decode SQL injection', 'Base64 encoded SQL injection.', 'Injection SQL encodée base64.', 'HIGH', 85, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["et web base64_decode sql injection", "T1190"]', 1, 0),
(2010151, 'SNORT', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1059'), 'ET WEB eval() function', 'eval() function in HTTP.', 'Fonction eval() dans HTTP.', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["et web eval() function", "T1059"]', 1, 0),
(2010152, 'SNORT', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1059'), 'ET WEB shell_exec() function', 'shell_exec() in HTTP.', 'shell_exec() dans HTTP.', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["et web shell_exec() function", "T1059"]', 1, 0),
(2010153, 'SNORT', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'ET WEB JSP webshell', 'JSP webshell upload pattern.', 'Pattern upload webshell JSP.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["et web jsp webshell", "T1190"]', 1, 0),
(2010500, 'SNORT', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'Snort WEB exploit 2010500', 'Web application exploit pattern.', 'Pattern d''exploit application web.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["snort web exploit 2010500", "T1190"]', 1, 0),
(2010501, 'SNORT', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'Snort WEB exploit 2010501', 'Web application exploit pattern.', 'Pattern d''exploit application web.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["snort web exploit 2010501", "T1190"]', 1, 0),
(2010502, 'SNORT', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'Snort WEB exploit 2010502', 'Web application exploit pattern.', 'Pattern d''exploit application web.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["snort web exploit 2010502", "T1190"]', 1, 0),
(2010503, 'SNORT', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'Snort WEB exploit 2010503', 'Web application exploit pattern.', 'Pattern d''exploit application web.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["snort web exploit 2010503", "T1190"]', 1, 0),
(2010504, 'SNORT', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'Snort WEB exploit 2010504', 'Web application exploit pattern.', 'Pattern d''exploit application web.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["snort web exploit 2010504", "T1190"]', 1, 0),
(2010505, 'SNORT', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'Snort WEB exploit 2010505', 'Web application exploit pattern.', 'Pattern d''exploit application web.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["snort web exploit 2010505", "T1190"]', 1, 0),
(2010506, 'SNORT', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'Snort WEB exploit 2010506', 'Web application exploit pattern.', 'Pattern d''exploit application web.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["snort web exploit 2010506", "T1190"]', 1, 0),
(2010507, 'SNORT', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'Snort WEB exploit 2010507', 'Web application exploit pattern.', 'Pattern d''exploit application web.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["snort web exploit 2010507", "T1190"]', 1, 0),
(2010508, 'SNORT', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'Snort WEB exploit 2010508', 'Web application exploit pattern.', 'Pattern d''exploit application web.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["snort web exploit 2010508", "T1190"]', 1, 0),
(2010509, 'SNORT', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'Snort WEB exploit 2010509', 'Web application exploit pattern.', 'Pattern d''exploit application web.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["snort web exploit 2010509", "T1190"]', 1, 0),
(2010510, 'SNORT', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'Snort WEB exploit 2010510', 'Web application exploit pattern.', 'Pattern d''exploit application web.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["snort web exploit 2010510", "T1190"]', 1, 0),
(2010511, 'SNORT', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'Snort WEB exploit 2010511', 'Web application exploit pattern.', 'Pattern d''exploit application web.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["snort web exploit 2010511", "T1190"]', 1, 0),
(2010512, 'SNORT', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'Snort WEB exploit 2010512', 'Web application exploit pattern.', 'Pattern d''exploit application web.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["snort web exploit 2010512", "T1190"]', 1, 0),
(2010513, 'SNORT', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'Snort WEB exploit 2010513', 'Web application exploit pattern.', 'Pattern d''exploit application web.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["snort web exploit 2010513", "T1190"]', 1, 0),
(2010514, 'SNORT', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'Snort WEB exploit 2010514', 'Web application exploit pattern.', 'Pattern d''exploit application web.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["snort web exploit 2010514", "T1190"]', 1, 0),
(2010515, 'SNORT', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'Snort WEB exploit 2010515', 'Web application exploit pattern.', 'Pattern d''exploit application web.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["snort web exploit 2010515", "T1190"]', 1, 0),
(2010517, 'SNORT', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'Snort WEB exploit 2010517', 'Web application exploit pattern.', 'Pattern d''exploit application web.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["snort web exploit 2010517", "T1190"]', 1, 0),
(2010518, 'SNORT', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'Snort WEB exploit 2010518', 'Web application exploit pattern.', 'Pattern d''exploit application web.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["snort web exploit 2010518", "T1190"]', 1, 0),
(2010519, 'SNORT', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'Snort WEB exploit 2010519', 'Web application exploit pattern.', 'Pattern d''exploit application web.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Bloquer l''IP source (permanent pour SQL injection).
• Auditer les logs : grep "UNION\|SELECT\|<script>" /var/log/nginx/access.log

À vérifier :
• Quelle URL exacte a été attaquée.
• Si l''application utilise des prepared statements.
• Vérifier la base de données pour modifications suspectes.

À corriger :
• Implémenter prepared statements (PDO, parameterized queries).
• Installer ModSecurity (OWASP CRS) ou Cloudflare WAF.
• Audit de sécurité de l''application web.', '["snort web exploit 2010519", "T1190"]', 1, 0),
(2017471, 'SNORT', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071'), 'ET MALWARE Cobalt Strike beacon', 'Cobalt Strike C2 beacon.', 'Beacon C2 Cobalt Strike.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["et malware cobalt strike beacon", "T1071"]', 1, 0),
(2024792, 'SNORT', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071'), 'ET MALWARE Emotet C2', 'Emotet command-and-control.', 'Command-and-control Emotet.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["et malware emotet c2", "T1071"]', 1, 0),
(2025392, 'SNORT', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071'), 'ET MALWARE TrickBot', 'TrickBot malware activity.', 'Activité malware TrickBot.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["et malware trickbot", "T1071"]', 1, 0),
(2027895, 'SNORT', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071'), 'ET MALWARE Qakbot', 'Qakbot malware C2.', 'C2 malware Qakbot.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["et malware qakbot", "T1071"]', 1, 0),
(2029186, 'SNORT', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071'), 'ET MALWARE Generic backdoor', 'Generic backdoor traffic.', 'Trafic backdoor générique.', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["et malware generic backdoor", "T1071"]', 1, 0),
(2030245, 'SNORT', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071'), 'ET MALWARE IcedID', 'IcedID banking trojan.', 'Trojan bancaire IcedID.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["et malware icedid", "T1071"]', 1, 0),
(2031148, 'SNORT', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1003'), 'ET MALWARE Generic stealer', 'Generic credential stealer.', 'Voleur d''identifiants générique.', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["et malware generic stealer", "T1003"]', 1, 0),
(2032596, 'SNORT', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071'), 'ET MALWARE Lokibot', 'Lokibot stealer activity.', 'Activité stealer Lokibot.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["et malware lokibot", "T1071"]', 1, 0),
(2033748, 'SNORT', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071'), 'ET MALWARE AsyncRAT', 'AsyncRAT remote access trojan.', 'Remote access trojan AsyncRAT.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["et malware asyncrat", "T1071"]', 1, 0),
(2030000, 'SNORT', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071'), 'Snort MALWARE pattern 2030000', 'Malware traffic pattern detected.', 'Pattern de trafic malware détecté.', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["snort malware pattern 2030000", "T1071"]', 1, 0),
(2030001, 'SNORT', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071'), 'Snort MALWARE pattern 2030001', 'Malware traffic pattern detected.', 'Pattern de trafic malware détecté.', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["snort malware pattern 2030001", "T1071"]', 1, 0),
(2030002, 'SNORT', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071'), 'Snort MALWARE pattern 2030002', 'Malware traffic pattern detected.', 'Pattern de trafic malware détecté.', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["snort malware pattern 2030002", "T1071"]', 1, 0),
(2030003, 'SNORT', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071'), 'Snort MALWARE pattern 2030003', 'Malware traffic pattern detected.', 'Pattern de trafic malware détecté.', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["snort malware pattern 2030003", "T1071"]', 1, 0),
(2030004, 'SNORT', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071'), 'Snort MALWARE pattern 2030004', 'Malware traffic pattern detected.', 'Pattern de trafic malware détecté.', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["snort malware pattern 2030004", "T1071"]', 1, 0),
(2030005, 'SNORT', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071'), 'Snort MALWARE pattern 2030005', 'Malware traffic pattern detected.', 'Pattern de trafic malware détecté.', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["snort malware pattern 2030005", "T1071"]', 1, 0),
(2030006, 'SNORT', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071'), 'Snort MALWARE pattern 2030006', 'Malware traffic pattern detected.', 'Pattern de trafic malware détecté.', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["snort malware pattern 2030006", "T1071"]', 1, 0),
(2030007, 'SNORT', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071'), 'Snort MALWARE pattern 2030007', 'Malware traffic pattern detected.', 'Pattern de trafic malware détecté.', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["snort malware pattern 2030007", "T1071"]', 1, 0),
(2030008, 'SNORT', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071'), 'Snort MALWARE pattern 2030008', 'Malware traffic pattern detected.', 'Pattern de trafic malware détecté.', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["snort malware pattern 2030008", "T1071"]', 1, 0),
(2030009, 'SNORT', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071'), 'Snort MALWARE pattern 2030009', 'Malware traffic pattern detected.', 'Pattern de trafic malware détecté.', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["snort malware pattern 2030009", "T1071"]', 1, 0),
(2030010, 'SNORT', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071'), 'Snort MALWARE pattern 2030010', 'Malware traffic pattern detected.', 'Pattern de trafic malware détecté.', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["snort malware pattern 2030010", "T1071"]', 1, 0),
(2030011, 'SNORT', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071'), 'Snort MALWARE pattern 2030011', 'Malware traffic pattern detected.', 'Pattern de trafic malware détecté.', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["snort malware pattern 2030011", "T1071"]', 1, 0),
(2030012, 'SNORT', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071'), 'Snort MALWARE pattern 2030012', 'Malware traffic pattern detected.', 'Pattern de trafic malware détecté.', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["snort malware pattern 2030012", "T1071"]', 1, 0),
(2030013, 'SNORT', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071'), 'Snort MALWARE pattern 2030013', 'Malware traffic pattern detected.', 'Pattern de trafic malware détecté.', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["snort malware pattern 2030013", "T1071"]', 1, 0),
(2030014, 'SNORT', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071'), 'Snort MALWARE pattern 2030014', 'Malware traffic pattern detected.', 'Pattern de trafic malware détecté.', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["snort malware pattern 2030014", "T1071"]', 1, 0),
(2030015, 'SNORT', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071'), 'Snort MALWARE pattern 2030015', 'Malware traffic pattern detected.', 'Pattern de trafic malware détecté.', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["snort malware pattern 2030015", "T1071"]', 1, 0),
(2030016, 'SNORT', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071'), 'Snort MALWARE pattern 2030016', 'Malware traffic pattern detected.', 'Pattern de trafic malware détecté.', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["snort malware pattern 2030016", "T1071"]', 1, 0),
(2030017, 'SNORT', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071'), 'Snort MALWARE pattern 2030017', 'Malware traffic pattern detected.', 'Pattern de trafic malware détecté.', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["snort malware pattern 2030017", "T1071"]', 1, 0),
(2030018, 'SNORT', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071'), 'Snort MALWARE pattern 2030018', 'Malware traffic pattern detected.', 'Pattern de trafic malware détecté.', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["snort malware pattern 2030018", "T1071"]', 1, 0),
(2030019, 'SNORT', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071'), 'Snort MALWARE pattern 2030019', 'Malware traffic pattern detected.', 'Pattern de trafic malware détecté.', 'CRITICAL', 90, 'BLOCK', 'Action immédiate :
• Isoler la machine du réseau si possible.
• Lancer scan complet : clamscan -r --infected /

À vérifier :
• Quels fichiers sont infectés.
• Connexions sortantes suspectes : ss -tunap

À corriger :
• Quarantaine ou suppression des fichiers infectés.
• Réinstallation propre si rootkit confirmé.
• Mise à jour antivirus + signatures.', '["snort malware pattern 2030019", "T1071"]', 1, 0),
(2030200, 'SNORT', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1486'), 'ET MALWARE Wannacry ransomware', 'Wannacry ransomware C2 communication.', 'Communication C2 ransomware Wannacry.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• ⚠ URGENCE : isoler la machine immédiatement.
• DÉBRANCHER le câble réseau.
• Ne PAS payer la rançon.

À vérifier :
• Étendue de la compromission (autres machines ?).
• Existence de sauvegardes intactes.
• Identifier la variante de ransomware (notes laissées).

À corriger :
• Restauration depuis sauvegarde HORS-LIGNE.
• Réinstallation système complète.
• Forensics pour comprendre le vecteur d''entrée.
• Notification ANTIC/ARTCI dans 72h si données perso.', '["et malware wannacry ransomware", "T1486"]', 1, 0),
(2030201, 'SNORT', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1486'), 'ET MALWARE NotPetya ransomware', 'NotPetya ransomware C2 communication.', 'Communication C2 ransomware NotPetya.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• ⚠ URGENCE : isoler la machine immédiatement.
• DÉBRANCHER le câble réseau.
• Ne PAS payer la rançon.

À vérifier :
• Étendue de la compromission (autres machines ?).
• Existence de sauvegardes intactes.
• Identifier la variante de ransomware (notes laissées).

À corriger :
• Restauration depuis sauvegarde HORS-LIGNE.
• Réinstallation système complète.
• Forensics pour comprendre le vecteur d''entrée.
• Notification ANTIC/ARTCI dans 72h si données perso.', '["et malware notpetya ransomware", "T1486"]', 1, 0),
(2030202, 'SNORT', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1486'), 'ET MALWARE Locky ransomware', 'Locky ransomware C2 communication.', 'Communication C2 ransomware Locky.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• ⚠ URGENCE : isoler la machine immédiatement.
• DÉBRANCHER le câble réseau.
• Ne PAS payer la rançon.

À vérifier :
• Étendue de la compromission (autres machines ?).
• Existence de sauvegardes intactes.
• Identifier la variante de ransomware (notes laissées).

À corriger :
• Restauration depuis sauvegarde HORS-LIGNE.
• Réinstallation système complète.
• Forensics pour comprendre le vecteur d''entrée.
• Notification ANTIC/ARTCI dans 72h si données perso.', '["et malware locky ransomware", "T1486"]', 1, 0),
(2030203, 'SNORT', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1486'), 'ET MALWARE Cerber ransomware', 'Cerber ransomware C2 communication.', 'Communication C2 ransomware Cerber.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• ⚠ URGENCE : isoler la machine immédiatement.
• DÉBRANCHER le câble réseau.
• Ne PAS payer la rançon.

À vérifier :
• Étendue de la compromission (autres machines ?).
• Existence de sauvegardes intactes.
• Identifier la variante de ransomware (notes laissées).

À corriger :
• Restauration depuis sauvegarde HORS-LIGNE.
• Réinstallation système complète.
• Forensics pour comprendre le vecteur d''entrée.
• Notification ANTIC/ARTCI dans 72h si données perso.', '["et malware cerber ransomware", "T1486"]', 1, 0),
(2030204, 'SNORT', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1486'), 'ET MALWARE CryptoWall ransomware', 'CryptoWall ransomware C2 communication.', 'Communication C2 ransomware CryptoWall.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• ⚠ URGENCE : isoler la machine immédiatement.
• DÉBRANCHER le câble réseau.
• Ne PAS payer la rançon.

À vérifier :
• Étendue de la compromission (autres machines ?).
• Existence de sauvegardes intactes.
• Identifier la variante de ransomware (notes laissées).

À corriger :
• Restauration depuis sauvegarde HORS-LIGNE.
• Réinstallation système complète.
• Forensics pour comprendre le vecteur d''entrée.
• Notification ANTIC/ARTCI dans 72h si données perso.', '["et malware cryptowall ransomware", "T1486"]', 1, 0),
(2030205, 'SNORT', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1486'), 'ET MALWARE Phobos ransomware', 'Phobos ransomware C2 communication.', 'Communication C2 ransomware Phobos.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• ⚠ URGENCE : isoler la machine immédiatement.
• DÉBRANCHER le câble réseau.
• Ne PAS payer la rançon.

À vérifier :
• Étendue de la compromission (autres machines ?).
• Existence de sauvegardes intactes.
• Identifier la variante de ransomware (notes laissées).

À corriger :
• Restauration depuis sauvegarde HORS-LIGNE.
• Réinstallation système complète.
• Forensics pour comprendre le vecteur d''entrée.
• Notification ANTIC/ARTCI dans 72h si données perso.', '["et malware phobos ransomware", "T1486"]', 1, 0),
(2030206, 'SNORT', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1486'), 'ET MALWARE Dharma ransomware', 'Dharma ransomware C2 communication.', 'Communication C2 ransomware Dharma.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• ⚠ URGENCE : isoler la machine immédiatement.
• DÉBRANCHER le câble réseau.
• Ne PAS payer la rançon.

À vérifier :
• Étendue de la compromission (autres machines ?).
• Existence de sauvegardes intactes.
• Identifier la variante de ransomware (notes laissées).

À corriger :
• Restauration depuis sauvegarde HORS-LIGNE.
• Réinstallation système complète.
• Forensics pour comprendre le vecteur d''entrée.
• Notification ANTIC/ARTCI dans 72h si données perso.', '["et malware dharma ransomware", "T1486"]', 1, 0),
(2030207, 'SNORT', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1486'), 'ET MALWARE LockBit ransomware', 'LockBit ransomware C2 communication.', 'Communication C2 ransomware LockBit.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• ⚠ URGENCE : isoler la machine immédiatement.
• DÉBRANCHER le câble réseau.
• Ne PAS payer la rançon.

À vérifier :
• Étendue de la compromission (autres machines ?).
• Existence de sauvegardes intactes.
• Identifier la variante de ransomware (notes laissées).

À corriger :
• Restauration depuis sauvegarde HORS-LIGNE.
• Réinstallation système complète.
• Forensics pour comprendre le vecteur d''entrée.
• Notification ANTIC/ARTCI dans 72h si données perso.', '["et malware lockbit ransomware", "T1486"]', 1, 0),
(2030208, 'SNORT', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1486'), 'ET MALWARE Conti ransomware', 'Conti ransomware C2 communication.', 'Communication C2 ransomware Conti.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• ⚠ URGENCE : isoler la machine immédiatement.
• DÉBRANCHER le câble réseau.
• Ne PAS payer la rançon.

À vérifier :
• Étendue de la compromission (autres machines ?).
• Existence de sauvegardes intactes.
• Identifier la variante de ransomware (notes laissées).

À corriger :
• Restauration depuis sauvegarde HORS-LIGNE.
• Réinstallation système complète.
• Forensics pour comprendre le vecteur d''entrée.
• Notification ANTIC/ARTCI dans 72h si données perso.', '["et malware conti ransomware", "T1486"]', 1, 0),
(2030209, 'SNORT', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1486'), 'ET MALWARE BlackCat ransomware', 'BlackCat ransomware C2 communication.', 'Communication C2 ransomware BlackCat.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• ⚠ URGENCE : isoler la machine immédiatement.
• DÉBRANCHER le câble réseau.
• Ne PAS payer la rançon.

À vérifier :
• Étendue de la compromission (autres machines ?).
• Existence de sauvegardes intactes.
• Identifier la variante de ransomware (notes laissées).

À corriger :
• Restauration depuis sauvegarde HORS-LIGNE.
• Réinstallation système complète.
• Forensics pour comprendre le vecteur d''entrée.
• Notification ANTIC/ARTCI dans 72h si données perso.', '["et malware blackcat ransomware", "T1486"]', 1, 0),
(2030210, 'SNORT', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1486'), 'ET MALWARE Akira ransomware', 'Akira ransomware C2 communication.', 'Communication C2 ransomware Akira.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• ⚠ URGENCE : isoler la machine immédiatement.
• DÉBRANCHER le câble réseau.
• Ne PAS payer la rançon.

À vérifier :
• Étendue de la compromission (autres machines ?).
• Existence de sauvegardes intactes.
• Identifier la variante de ransomware (notes laissées).

À corriger :
• Restauration depuis sauvegarde HORS-LIGNE.
• Réinstallation système complète.
• Forensics pour comprendre le vecteur d''entrée.
• Notification ANTIC/ARTCI dans 72h si données perso.', '["et malware akira ransomware", "T1486"]', 1, 0),
(2030211, 'SNORT', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1486'), 'ET MALWARE REvil ransomware', 'REvil ransomware C2 communication.', 'Communication C2 ransomware REvil.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• ⚠ URGENCE : isoler la machine immédiatement.
• DÉBRANCHER le câble réseau.
• Ne PAS payer la rançon.

À vérifier :
• Étendue de la compromission (autres machines ?).
• Existence de sauvegardes intactes.
• Identifier la variante de ransomware (notes laissées).

À corriger :
• Restauration depuis sauvegarde HORS-LIGNE.
• Réinstallation système complète.
• Forensics pour comprendre le vecteur d''entrée.
• Notification ANTIC/ARTCI dans 72h si données perso.', '["et malware revil ransomware", "T1486"]', 1, 0),
(2030212, 'SNORT', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1486'), 'ET MALWARE Ryuk ransomware', 'Ryuk ransomware C2 communication.', 'Communication C2 ransomware Ryuk.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• ⚠ URGENCE : isoler la machine immédiatement.
• DÉBRANCHER le câble réseau.
• Ne PAS payer la rançon.

À vérifier :
• Étendue de la compromission (autres machines ?).
• Existence de sauvegardes intactes.
• Identifier la variante de ransomware (notes laissées).

À corriger :
• Restauration depuis sauvegarde HORS-LIGNE.
• Réinstallation système complète.
• Forensics pour comprendre le vecteur d''entrée.
• Notification ANTIC/ARTCI dans 72h si données perso.', '["et malware ryuk ransomware", "T1486"]', 1, 0),
(2030213, 'SNORT', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1486'), 'ET MALWARE Maze ransomware', 'Maze ransomware C2 communication.', 'Communication C2 ransomware Maze.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• ⚠ URGENCE : isoler la machine immédiatement.
• DÉBRANCHER le câble réseau.
• Ne PAS payer la rançon.

À vérifier :
• Étendue de la compromission (autres machines ?).
• Existence de sauvegardes intactes.
• Identifier la variante de ransomware (notes laissées).

À corriger :
• Restauration depuis sauvegarde HORS-LIGNE.
• Réinstallation système complète.
• Forensics pour comprendre le vecteur d''entrée.
• Notification ANTIC/ARTCI dans 72h si données perso.', '["et malware maze ransomware", "T1486"]', 1, 0),
(2030214, 'SNORT', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1486'), 'ET MALWARE Egregor ransomware', 'Egregor ransomware C2 communication.', 'Communication C2 ransomware Egregor.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• ⚠ URGENCE : isoler la machine immédiatement.
• DÉBRANCHER le câble réseau.
• Ne PAS payer la rançon.

À vérifier :
• Étendue de la compromission (autres machines ?).
• Existence de sauvegardes intactes.
• Identifier la variante de ransomware (notes laissées).

À corriger :
• Restauration depuis sauvegarde HORS-LIGNE.
• Réinstallation système complète.
• Forensics pour comprendre le vecteur d''entrée.
• Notification ANTIC/ARTCI dans 72h si données perso.', '["et malware egregor ransomware", "T1486"]', 1, 0),
(2403302, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1499'), 'ET DOS Possible Slowloris', 'Slowloris DoS attack pattern.', 'Pattern attaque DoS Slowloris.', 'HIGH', 90, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["et dos possible slowloris", "T1499"]', 1, 0),
(2403303, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1498'), 'ET DOS HOIC tool', 'HOIC DDoS tool detected.', 'Outil DDoS HOIC détecté.', 'HIGH', 90, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["et dos hoic tool", "T1498"]', 1, 0),
(2403304, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1498'), 'ET DOS LOIC tool', 'LOIC DDoS tool detected.', 'Outil DDoS LOIC détecté.', 'HIGH', 90, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["et dos loic tool", "T1498"]', 1, 0),
(2403305, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1498'), 'ET DOS SYN flood', 'SYN flood attack pattern.', 'Pattern attaque SYN flood.', 'HIGH', 90, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["et dos syn flood", "T1498"]', 1, 0),
(2403306, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1498'), 'ET DOS UDP flood', 'UDP flood attack.', 'Attaque UDP flood.', 'HIGH', 90, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["et dos udp flood", "T1498"]', 1, 0),
(2403307, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1498'), 'ET DOS ICMP flood', 'ICMP flood (ping flood).', 'ICMP flood (ping flood).', 'MEDIUM', 80, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["et dos icmp flood", "T1498"]', 1, 0),
(2403308, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1499'), 'ET DOS HTTP flood', 'HTTP flood (Layer 7 DDoS).', 'HTTP flood (DDoS niveau 7).', 'HIGH', 90, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["et dos http flood", "T1499"]', 1, 0),
(2403309, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1498'), 'ET DOS DNS amplification', 'DNS amplification attack.', 'Attaque amplification DNS.', 'HIGH', 90, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["et dos dns amplification", "T1498"]', 1, 0),
(2403310, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1498'), 'ET DOS NTP amplification', 'NTP amplification attack.', 'Attaque amplification NTP.', 'HIGH', 90, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["et dos ntp amplification", "T1498"]', 1, 0),
(2403311, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1498'), 'ET DOS SSDP amplification', 'SSDP amplification attack.', 'Attaque amplification SSDP.', 'HIGH', 90, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["et dos ssdp amplification", "T1498"]', 1, 0),
(2008600, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1557.002'), 'ET POLICY ARP spoofing', 'ARP spoofing detected.', 'ARP spoofing détecté.', 'HIGH', 85, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["et policy arp spoofing", "T1557.002"]', 1, 0),
(2008601, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1557'), 'ET POLICY MAC flooding', 'MAC flooding attack.', 'Attaque MAC flooding.', 'HIGH', 85, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["et policy mac flooding", "T1557"]', 1, 0),
(2008602, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1499'), 'ET POLICY DHCP starvation', 'DHCP starvation attack.', 'Attaque DHCP starvation.', 'HIGH', 85, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["et policy dhcp starvation", "T1499"]', 1, 0),
(2008603, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1574'), 'ET POLICY VLAN hopping', 'VLAN hopping attempt.', 'Tentative VLAN hopping.', 'HIGH', 85, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["et policy vlan hopping", "T1574"]', 1, 0),
(2008604, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1557'), 'ET POLICY DNS spoofing', 'DNS spoofing pattern.', 'Pattern DNS spoofing.', 'HIGH', 85, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["et policy dns spoofing", "T1557"]', 1, 0),
(2403400, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1498'), 'Snort DOS/Network attack 2403400', 'Network-level attack pattern.', 'Pattern attaque niveau réseau.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["snort dos/network attack 2403400", "T1498"]', 1, 0),
(2403401, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1498'), 'Snort DOS/Network attack 2403401', 'Network-level attack pattern.', 'Pattern attaque niveau réseau.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["snort dos/network attack 2403401", "T1498"]', 1, 0),
(2403402, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1498'), 'Snort DOS/Network attack 2403402', 'Network-level attack pattern.', 'Pattern attaque niveau réseau.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["snort dos/network attack 2403402", "T1498"]', 1, 0),
(2403403, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1498'), 'Snort DOS/Network attack 2403403', 'Network-level attack pattern.', 'Pattern attaque niveau réseau.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["snort dos/network attack 2403403", "T1498"]', 1, 0),
(2403404, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1498'), 'Snort DOS/Network attack 2403404', 'Network-level attack pattern.', 'Pattern attaque niveau réseau.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["snort dos/network attack 2403404", "T1498"]', 1, 0),
(2403405, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1498'), 'Snort DOS/Network attack 2403405', 'Network-level attack pattern.', 'Pattern attaque niveau réseau.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["snort dos/network attack 2403405", "T1498"]', 1, 0),
(2403406, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1498'), 'Snort DOS/Network attack 2403406', 'Network-level attack pattern.', 'Pattern attaque niveau réseau.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["snort dos/network attack 2403406", "T1498"]', 1, 0),
(2403407, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1498'), 'Snort DOS/Network attack 2403407', 'Network-level attack pattern.', 'Pattern attaque niveau réseau.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["snort dos/network attack 2403407", "T1498"]', 1, 0),
(2403408, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1498'), 'Snort DOS/Network attack 2403408', 'Network-level attack pattern.', 'Pattern attaque niveau réseau.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["snort dos/network attack 2403408", "T1498"]', 1, 0),
(2403409, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1498'), 'Snort DOS/Network attack 2403409', 'Network-level attack pattern.', 'Pattern attaque niveau réseau.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["snort dos/network attack 2403409", "T1498"]', 1, 0),
(2403410, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1498'), 'Snort DOS/Network attack 2403410', 'Network-level attack pattern.', 'Pattern attaque niveau réseau.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["snort dos/network attack 2403410", "T1498"]', 1, 0),
(2403411, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1498'), 'Snort DOS/Network attack 2403411', 'Network-level attack pattern.', 'Pattern attaque niveau réseau.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["snort dos/network attack 2403411", "T1498"]', 1, 0),
(2403412, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1498'), 'Snort DOS/Network attack 2403412', 'Network-level attack pattern.', 'Pattern attaque niveau réseau.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["snort dos/network attack 2403412", "T1498"]', 1, 0),
(2403413, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1498'), 'Snort DOS/Network attack 2403413', 'Network-level attack pattern.', 'Pattern attaque niveau réseau.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["snort dos/network attack 2403413", "T1498"]', 1, 0),
(2403414, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1498'), 'Snort DOS/Network attack 2403414', 'Network-level attack pattern.', 'Pattern attaque niveau réseau.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["snort dos/network attack 2403414", "T1498"]', 1, 0),
(2403415, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1498'), 'Snort DOS/Network attack 2403415', 'Network-level attack pattern.', 'Pattern attaque niveau réseau.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["snort dos/network attack 2403415", "T1498"]', 1, 0),
(2403416, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1498'), 'Snort DOS/Network attack 2403416', 'Network-level attack pattern.', 'Pattern attaque niveau réseau.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["snort dos/network attack 2403416", "T1498"]', 1, 0),
(2403417, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1498'), 'Snort DOS/Network attack 2403417', 'Network-level attack pattern.', 'Pattern attaque niveau réseau.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["snort dos/network attack 2403417", "T1498"]', 1, 0),
(2403418, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1498'), 'Snort DOS/Network attack 2403418', 'Network-level attack pattern.', 'Pattern attaque niveau réseau.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["snort dos/network attack 2403418", "T1498"]', 1, 0),
(2403419, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1498'), 'Snort DOS/Network attack 2403419', 'Network-level attack pattern.', 'Pattern attaque niveau réseau.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["snort dos/network attack 2403419", "T1498"]', 1, 0),
(2403420, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1498'), 'Snort DOS/Network attack 2403420', 'Network-level attack pattern.', 'Pattern attaque niveau réseau.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["snort dos/network attack 2403420", "T1498"]', 1, 0),
(2403421, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1498'), 'Snort DOS/Network attack 2403421', 'Network-level attack pattern.', 'Pattern attaque niveau réseau.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["snort dos/network attack 2403421", "T1498"]', 1, 0),
(2403422, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1498'), 'Snort DOS/Network attack 2403422', 'Network-level attack pattern.', 'Pattern attaque niveau réseau.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["snort dos/network attack 2403422", "T1498"]', 1, 0),
(2403423, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1498'), 'Snort DOS/Network attack 2403423', 'Network-level attack pattern.', 'Pattern attaque niveau réseau.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["snort dos/network attack 2403423", "T1498"]', 1, 0),
(2403424, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1498'), 'Snort DOS/Network attack 2403424', 'Network-level attack pattern.', 'Pattern attaque niveau réseau.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["snort dos/network attack 2403424", "T1498"]', 1, 0),
(2403425, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1498'), 'Snort DOS/Network attack 2403425', 'Network-level attack pattern.', 'Pattern attaque niveau réseau.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["snort dos/network attack 2403425", "T1498"]', 1, 0),
(2403426, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1498'), 'Snort DOS/Network attack 2403426', 'Network-level attack pattern.', 'Pattern attaque niveau réseau.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["snort dos/network attack 2403426", "T1498"]', 1, 0),
(2403427, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1498'), 'Snort DOS/Network attack 2403427', 'Network-level attack pattern.', 'Pattern attaque niveau réseau.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["snort dos/network attack 2403427", "T1498"]', 1, 0),
(2403428, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1498'), 'Snort DOS/Network attack 2403428', 'Network-level attack pattern.', 'Pattern attaque niveau réseau.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["snort dos/network attack 2403428", "T1498"]', 1, 0),
(2403429, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1498'), 'Snort DOS/Network attack 2403429', 'Network-level attack pattern.', 'Pattern attaque niveau réseau.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["snort dos/network attack 2403429", "T1498"]', 1, 0),
(2403430, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1498'), 'Snort DOS/Network attack 2403430', 'Network-level attack pattern.', 'Pattern attaque niveau réseau.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["snort dos/network attack 2403430", "T1498"]', 1, 0),
(2403431, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1498'), 'Snort DOS/Network attack 2403431', 'Network-level attack pattern.', 'Pattern attaque niveau réseau.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["snort dos/network attack 2403431", "T1498"]', 1, 0),
(2403432, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1498'), 'Snort DOS/Network attack 2403432', 'Network-level attack pattern.', 'Pattern attaque niveau réseau.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["snort dos/network attack 2403432", "T1498"]', 1, 0),
(2403433, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1498'), 'Snort DOS/Network attack 2403433', 'Network-level attack pattern.', 'Pattern attaque niveau réseau.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["snort dos/network attack 2403433", "T1498"]', 1, 0),
(2403434, 'SNORT', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1498'), 'Snort DOS/Network attack 2403434', 'Network-level attack pattern.', 'Pattern attaque niveau réseau.', 'HIGH', 80, 'BLOCK', 'Action immédiate :
• Activer protection DDoS au pare-feu/cloud.
• Limiter le rate limiting des connexions.

À vérifier :
• Type d''attaque (volumétrique vs applicative).
• IPs sources (botnet ?).

À corriger :
• Configurer Cloudflare ou autre protection DDoS.
• Augmenter les ressources si attaque volumétrique.
• Bloquer les pays sources si attaque géolocalisée.', '["snort dos/network attack 2403434", "T1498"]', 1, 0),
(2034647, 'SNORT', 9, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'ET EXPLOIT Log4Shell CVE-2021-44228', 'Log4Shell CVE-2021-44228 exploit attempt.', 'Tentative exploit Log4Shell CVE-2021-44228.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• Bloquer l''IP attaquante.
• Vérifier la version du logiciel ciblé.

À vérifier :
• La CVE est-elle applicable à votre version ?
• Le serveur a-t-il été patché récemment ?

À corriger :
• Patcher d''urgence le logiciel concerné.
• apt upgrade ou yum update.
• Si exploitation réussie : forensics complet.', '["et exploit log4shell cve-2021-44228", "T1190"]', 1, 0),
(2035148, 'SNORT', 9, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'ET EXPLOIT Spring4Shell CVE-2022-22965', 'Spring4Shell CVE-2022-22965 exploit attempt.', 'Tentative exploit Spring4Shell CVE-2022-22965.', 'CRITICAL', 95, 'BLOCK', 'Action immédiate :
• Bloquer l''IP attaquante.
• Vérifier la version du logiciel ciblé.

À vérifier :
• La CVE est-elle applicable à votre version ?
• Le serveur a-t-il été patché récemment ?

À corriger :
• Patcher d''urgence le logiciel concerné.
• apt upgrade ou yum update.
• Si exploitation réussie : forensics complet.', '["et exploit spring4shell cve-2022-22965", "T1190"]', 1, 0);

-- ============================================================================
-- FIN signatures.sql - 380 signatures insérées
-- ============================================================================