# ℞ PharmaClair - Système de Gestion Officinale & Direction

**PharmaClair** est un système officinal complet, moderne et léger, développé **exclusivement avec la bibliothèque standard Python** (zéro dépendance externe). Il embarque un serveur HTTP multi-threadé, une base de données SQLite transactionnelle et une interface web réactive (Point de Vente, Direction, Stocks, Personnel).

---

## 🌟 Fonctionnalités Principales

### 🛒 1. Point de Vente (POS / Caisse)
- **Catalogue en direct** : Recherche instantanée de médicaments par nom ou référence.
- **Règle FEFO stricte (*First Expired, First Out*)** : Déstockage automatique priorisant les lots périmant le plus tôt.
- **Transparence pour l'employé** : Affichage visible des numéros de lot et dates de péremption dans le catalogue et dans le panier.
- **Modes de règlement** : Espèces, Mobile Money (Orange Money / MTN MoMo), Carte bancaire.
- **Calcul de monnaie automatique** et garantie d'idempotence des transactions (`idem`).

### 🧾 2. Reçus & Tickets de Caisse Officinaux
- Horodatage certifié : **Date et Heure exacte à la seconde** (fuseau horaire Douala GMT+1).
- Détail précis pour chaque ligne vendue : médicament, quantité, prix, **numéro de lot** et **date d'expiration**.
- Optimisation pour **imprimantes thermiques de caisse 80 mm** via `@media print`.

### 👑 3. Tableau de Bord Propriétaire / Direction
- **Indicateurs Clés du Jour (KPI)** : Chiffre d'affaires journalier, nombre de ventes, panier moyen, lots à risque (≤ 6 mois).
- **Consolidation des paiements** : Totaux en Espèces, Mobile Money et Carte.
- **Suivi de la performance des employés** : Chiffre d'affaires et volume de ventes par caissier, dernière transaction horodatée.
- **Fil d'activité en temps réel** des ventes de la journée avec aperçu immédiat des tickets.

### 💰 4. Clôture de Caisse Journalière (Z de Caisse)
- Saisie du fond de caisse initial et comptage physique des espèces.
- Rapprochement automatique entre les espèces théoriques attendues et les espèces comptées.
- Détection des écarts de caisse (surplus ou manquant) et rapport de clôture journalière.

### 👥 5. Gestion du Personnel & Rôles (RBAC)
- Gestion des rôles : Titulaire (`owner`), Caissier (`cashier`), Magasinier (`stock`).
- Création de comptes employés avec permissions granulaires (encaissement, blocage de lots).
- Sécurité renforcée : hachage PBKDF2-HMAC-SHA256 (200 000 itérations), verrouillage automatique après 5 échecs, et déverrouillage en un clic par le titulaire.

### 📦 6. Stocks, Lots & Traçabilité
- Suivi par lot, fournisseur, bon de livraison (BL) et date de péremption.
- Réception de livraisons et mise en stock immédiate.
- Blocage/déblocage manuel de lots suspects.
- Gestion des retours clients et mise en quarantaine.
- Export du journal des ventes au format **CSV**.

---

## 🚀 Démarrage Rapide

### Prérequis
- Python 3.9+ (Bibliothèque standard uniquement, aucune installation `pip` requise).

### Lancement
```bash
python pharmaclair.py
```

L'application est immédiatement accessible dans votre navigateur :
👉 **http://localhost:8000**

---

## 🔐 Comptes de Démonstration

| Utilisateur | Mot de passe | Rôle | Permissions |
| :--- | :--- | :--- | :--- |
| `titulaire` | `admin123` | **Titulaire / Direction** | Accès total : Direction, Personnel, Caisse, Stocks, Exports |
| `caissier1` | `caisse123` | **Caissier** | Caisse / Vente, consultation des stocks, ses ventes |
| `caissier2` | `caisse123` | **Caissier** | Caisse / Vente, consultation des stocks, ses ventes |
| `magasinier` | `stock123` | **Magasinier** | Réceptions, blocage de lots, consultation des stocks |

---

## ⚙️ Configuration (Variables d'environnement)

- `PORT` : Port d'écoute du serveur HTTP (défaut : `8000`).
- `DB` : Fichier de base de données SQLite (défaut : `pharmaclair.db`).
- `EXPIRY_MONTH_RULE` : Règle de péremption pour les dates au format `AAAA-MM` (`end` pour dernier jour du mois, `start` pour premier jour du mois).

---

## 📄 Licence
Sous licence MIT. Libre d'utilisation et d'adaptation pour les officines de pharmacie.
