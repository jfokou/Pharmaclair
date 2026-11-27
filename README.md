# ℞ PharmaClair - Système de Gestion Officinale & Direction

[![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/new)

**PharmaClair** est un système officinal complet, moderne et léger, développé **exclusivement avec la bibliothèque standard Python** (zéro dépendance externe). Il embarque un serveur HTTP multi-threadé, une base de données SQLite transactionnelle et une interface web réactive (Point de Vente, Direction, Clients & Ordonnances, Rappels SMS, Stocks, Pointage du Personnel, Vidéosurveillance).

---

## 🌐 Déploiement Cloud Web 24h/24 avec Railway (Recommandé)

Vous pouvez héberger **PharmaClair** gratuitement et en continu sur le Cloud avec **Railway** afin qu'il soit accessible depuis n'importe quel ordinateur, tablette ou smartphone sans dépendre de votre machine locale.

### Étapes de déploiement sur Railway :
1. Connectez-vous sur **[Railway.com](https://railway.com)** avec votre compte GitHub.
2. Cliquez sur **New Project** (Nouveau projet) ➔ **Deploy from GitHub repo**.
3. Sélectionnez le dépôt **`jfokou/Pharmaclair`**. Railway détecte automatiquement la configuration et lance le déploiement.
4. Une fois le projet créé, cliquez sur la boîte du service **Pharmaclair** ➔ onglet **Settings**.
5. Dans la section **Public Networking**, cliquez sur **`⚡ Generate Domain`** (entrez le port `8000` si demandé).
6. Votre application est immédiatement en ligne avec son adresse publique permanente (ex: `https://pharmaclair-production.up.railway.app`) !

---

### Alternative : Autres hébergeurs Cloud
- **Koyeb** : *Create Service* ➔ *GitHub* ➔ Sélectionner `jfokou/Pharmaclair` ➔ Détection automatique du `Dockerfile`.
- **Render** : *New Web Service* ➔ Sélectionner `jfokou/Pharmaclair` ➔ Build Command vide, Start Command `python pharmaclair.py`.

---

## 🌟 Fonctionnalités Principales

### 🛒 1. Point de Vente (POS / Caisse)
- **Catalogue en direct** : Recherche instantanée de médicaments par nom ou référence.
- **Règle FEFO stricte (*First Expired, First Out*)** : Déstockage automatique priorisant les lots périmant le plus tôt.
- **Transparence pour l'employé** : Affichage visible des numéros de lot et dates de péremption dans le catalogue et dans le panier.
- **Rattachement Client & Ordonnance** : Association d'un patient et de son ordonnance lors de l'encaissement.
- **Modes de règlement** : Espèces, Mobile Money (Orange Money / MTN MoMo), Carte bancaire.
- **Calcul de monnaie automatique** et garantie d'idempotence des transactions (`idem`).

### 👥 2. Répertoire Clients & Gestion des Ordonnances
- Fiches patients complètes avec numéro de téléphone, médecin traitant et historique.
- Suivi des ordonnances avec posologie, durée de traitement et **compteur de renouvellements autorisés / restants**.
- Décrémentation automatique des renouvellements à chaque délivrance.

### 📱 3. Rappels SMS & Notifications Automatisées
- Module de notifications SMS automatiques pour avertir les patients chroniques de renouveler leur traitement avant rupture.
- Historique d'envoi et journal d'audit des messages envoyés aux patients.

### 🧾 4. Reçus & Tickets de Caisse Officinaux
- Horodatage certifié : **Date et Heure exacte à la seconde** (fuseau horaire Douala GMT+1).
- Détail précis pour chaque ligne vendue : médicament, quantité, prix, **numéro de lot** et **date d'expiration**.
- Optimisation pour **imprimantes thermiques de caisse 80 mm** via `@media print`.

### 👑 5. Tableau de Bord Propriétaire / Direction
- **Indicateurs Clés du Jour (KPI)** : Chiffre d'affaires journalier, nombre de ventes, panier moyen, lots à risque (≤ 6 mois).
- **Consolidation des paiements** : Totaux en Espèces, Mobile Money et Carte.
- **Suivi de la performance des employés** : Chiffre d'affaires et volume de ventes par caissier, dernière transaction horodatée.
- **Fil d'activité en temps réel** des ventes de la journée avec aperçu immédiat des tickets.

### 💰 6. Clôture de Caisse Journalière (Z de Caisse)
- Saisie du fond de caisse initial et comptage physique des espèces.
- Rapprochement automatique entre les espèces théoriques attendues et les espèces comptées.
- Détection des écarts de caisse (surplus ou manquant) et rapport de clôture journalière.

### ⏱️ 7. Registre de Pointage du Personnel (Heures d'Arrivée)
- Enregistrement automatique des connexions de chaque employé avec date et heure précise d'arrivée.
- Statut en direct (En service / Déconnecté) pour le titulaire de l'officine.

### 📹 8. Grille de Vidéosurveillance Officine
- Surveillance visuelle des zones critiques : Caisse principale, Espace Délivrance, Allée Officine, Réserve & Frigo Stock.

### 📦 9. Stocks, Lots & Traçabilité
- Suivi par lot, fournisseur, bon de livraison (BL) et date de péremption.
- Réception de livraisons et mise en stock immédiate.
- Blocage/déblocage manuel de lots suspects.
- Gestion des retours clients et mise en quarantaine.
- Export du journal des ventes au format **CSV**.

---

## 🚀 Démarrage en Local

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
| `titulaire` | `admin123` | **Titulaire / Direction** | Accès total : Direction, Personnel, Caisse, Stocks, Exports, Pointage, Caméras |
| `caissier1` | `caisse123` | **Caissier** | Caisse / Vente, consultation des stocks, ses ventes |
| `caissier2` | `caisse123` | **Caissier** | Caisse / Vente, consultation des stocks, ses ventes |
| `magasinier` | `stock123` | **Magasinier** | Réceptions, blocage de lots, consultation des stocks |

---

## ⚙️ Configuration (Variables d'environnement)

- `PORT` : Port d'écoute du serveur HTTP (défaut : `8000`, s'adapte automatiquement sur le Cloud à `10000` ou variable `PORT`).
- `DB` : Fichier de base de données SQLite (défaut : `pharmaclair.db`).
- `EXPIRY_MONTH_RULE` : Règle de péremption pour les dates au format `AAAA-MM` (`end` pour dernier jour du mois, `start` pour premier jour du mois).

---

## 📄 Licence
Sous licence MIT. Libre d'utilisation et d'adaptation pour les officines de pharmacie.
