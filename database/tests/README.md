# Tests automatisés - Module 2

Suite de tests pour valider l'installation et l'intégrité de la base de données SIEM Africa.

## Lancer tous les tests

```bash
sudo ./tests/run_all_tests.sh
```

## Lancer un test individuel

```bash
sudo ./tests/test_schema.sh
sudo ./tests/test_signatures.sh
sudo ./tests/test_relationships.sh
sudo ./tests/test_performance.sh
sudo ./tests/test_filters.sh
```

## Variable d'environnement

Par défaut, les tests utilisent `/var/lib/siem-africa/siem.db`.
Pour tester une autre BDD :

```bash
DB_PATH=/tmp/test.db ./tests/test_schema.sh
```

## Description des tests

| Test | Vérifie |
|------|---------|
| `test_schema.sh` | 22 tables, 3 vues, foreign keys, WAL mode |
| `test_signatures.sh` | 380 signatures (190+190), mapping MITRE, sévérités |
| `test_relationships.sh` | Intégrité référentielle, foreign_key_check, integrity_check |
| `test_performance.sh` | Temps de réponse des requêtes critiques |
| `test_filters.sh` | 5 mécanismes de gestion des faux positifs |

## Codes de sortie

- `0` : tous les tests sont passés
- `1` : au moins un test a échoué
