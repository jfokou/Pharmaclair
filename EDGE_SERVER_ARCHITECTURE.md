# ℞ PharmaClair — Architecture Serveur Local (Edge Server)

Ce document spécifie l'architecture de déploiement **Serveur Local (Edge Server)** pour les officines disposant de **plusieurs postes de caisse simultanés** avec une connexion Internet instable ou intermittente.

---

## 1. Principe Architectural

Alors que la version **PWA Offline-First** suffit pour une officine à 1 caisse active hors-ligne, une officine avec **2 à 10 caisses** doit éviter que deux caissiers hors-ligne vendent la même dernière boîte d'un médicament.

Le **Edge Server** résout ce problème :
1. Un petit ordinateur local (Mini-PC / Serveur) fait office de serveur central de l'officine sur le réseau local (LAN Ethernet / Wi-Fi).
2. Tous les postes de caisse (PC, tablettes) se connectent en local à `http://pharmaclair.local:8000` (ou l'IP fixe `http://192.168.1.200:8000`).
3. **Stock partagé transactionnel en temps réel** : Les déductions FEFO sont atomiques sur la base SQLite locale.
4. **Synchronisation Cloud Automatique** : Le Edge Server synchronise silencieusement vers le Cloud Railway (`https://kind-heart-production-abf64fb4.up.railway.app/`) dès qu'Internet est disponible, permettant au **Titulaire** de consulter l'application mobile à distance.

---

## 2. Matériel Recommandé

- **Mini-PC / Serveur** : Intel N100 / Core i3, 8 Go RAM, SSD NVMe 256 Go (ex: Beelink, Intel NUC, Dell OptiPlex Micro).
- **Alimentation sécurisée** : Onduleur (UPS) 650 VA minimum indispensable contre les coupures électriques pour protéger la base de données SQLite et le routeur.
- **Réseau** : Switch Gigabit Ethernet + Routeur Wi-Fi dédié aux tablettes/caisses.
- **Système d'exploitation** : Ubuntu Server 24.04 LTS ou Debian 12 (léger, stable, sans redémarrage forcé).

---

## 3. Sécurité & Sauvegardes

1. **Isolation Réseau** : Le Edge Server n'est pas exposé directement sur Internet ; il initie uniquement des connexions HTTPS sortantes vers le serveur Cloud Railway.
2. **Authentification & Permissions** : Chaque caisse est enregistrée dans `device_enrollments` avec un jeton unique.
3. **Sauvegarde Chiffrée Automatique** :
   - Cron quotidien de sauvegarde SQLite (`sqlite3 pharmaclair.db ".backup backup.db"`).
   - Chiffrement AES-256 avant copie sur clé USB externe et synchronisation chiffrée vers le Cloud.
4. **Reprise après coupure électrique** :
   - SQLite avec mode `WAL` (`PRAGMA journal_mode=WAL;`) et `synchronous=FULL` garantit zéro corruption de données en cas de perte brutale de courant.

---

## 4. Procédure d'Installation Rapide (Linux / Ubuntu)

```bash
# 1. Cloner le dépôt officiel
git clone https://github.com/jfokou/Pharmaclair.git /opt/pharmaclair
cd /opt/pharmaclair

# 2. Démarrer en mode service systemd (toujours actif)
sudo python3 pharmaclair.py
```

### Configuration `systemd` (`/etc/systemd/system/pharmaclair-edge.service`)
```ini
[Unit]
Description=PharmaClair Local Edge Server
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/pharmaclair
ExecStart=/usr/bin/python3 -u /opt/pharmaclair/pharmaclair.py
Restart=always
RestartSec=3
Environment=PORT=8000
Environment=DB=/opt/pharmaclair/pharmaclair.db

[Install]
WantedBy=multi-user.target
```

Activation :
```bash
sudo systemctl enable pharmaclair-edge
sudo systemctl start pharmaclair-edge
```
