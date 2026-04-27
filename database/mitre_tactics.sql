-- ============================================================================
-- SIEM AFRICA - Module 2
-- database/mitre_tactics.sql - Les 14 tactiques officielles MITRE ATT&CK
-- ============================================================================
-- Source : https://attack.mitre.org/tactics/enterprise/
-- ============================================================================

INSERT OR IGNORE INTO mitre_tactics (tactic_id, name, description, description_fr, url, display_order) VALUES
('TA0043', 'Reconnaissance', 'Gathering information to plan future adversary operations', 'Collecte d''informations pour planifier les opérations adverses futures', 'https://attack.mitre.org/tactics/TA0043/', 1),
('TA0042', 'Resource Development', 'Establishing resources to support operations', 'Acquisition de ressources pour supporter les opérations', 'https://attack.mitre.org/tactics/TA0042/', 2),
('TA0001', 'Initial Access', 'Getting into your network', 'Obtenir un accès initial au réseau cible', 'https://attack.mitre.org/tactics/TA0001/', 3),
('TA0002', 'Execution', 'Running malicious code', 'Exécution de code malveillant', 'https://attack.mitre.org/tactics/TA0002/', 4),
('TA0003', 'Persistence', 'Maintaining foothold', 'Maintien d''un point d''accès dans le système', 'https://attack.mitre.org/tactics/TA0003/', 5),
('TA0004', 'Privilege Escalation', 'Gaining higher-level permissions', 'Obtention de privilèges plus élevés', 'https://attack.mitre.org/tactics/TA0004/', 6),
('TA0005', 'Defense Evasion', 'Avoiding detection', 'Évasion des mécanismes de détection', 'https://attack.mitre.org/tactics/TA0005/', 7),
('TA0006', 'Credential Access', 'Stealing account names and passwords', 'Vol de noms de compte et mots de passe', 'https://attack.mitre.org/tactics/TA0006/', 8),
('TA0007', 'Discovery', 'Figuring out your environment', 'Exploration de l''environnement compromis', 'https://attack.mitre.org/tactics/TA0007/', 9),
('TA0008', 'Lateral Movement', 'Moving through your environment', 'Déplacement latéral dans le réseau', 'https://attack.mitre.org/tactics/TA0008/', 10),
('TA0009', 'Collection', 'Gathering data of interest to the goal', 'Collecte de données d''intérêt pour l''objectif', 'https://attack.mitre.org/tactics/TA0009/', 11),
('TA0011', 'Command and Control', 'Communicating with compromised systems', 'Communication avec les systèmes compromis', 'https://attack.mitre.org/tactics/TA0011/', 12),
('TA0010', 'Exfiltration', 'Stealing data', 'Exfiltration de données volées', 'https://attack.mitre.org/tactics/TA0010/', 13),
('TA0040', 'Impact', 'Manipulate, interrupt, or destroy systems', 'Manipulation, interruption ou destruction des systèmes', 'https://attack.mitre.org/tactics/TA0040/', 14);
