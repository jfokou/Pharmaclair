# ℞ PharmaClair - Système de Gestion Officinale & Direction

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/jfokou/Pharmaclair)

**PharmaClair** est un système officinal complet, moderne et léger, développé **exclusivement avec la bibliothèque standard Python** (zéro dépendance externe). Il embarque un serveur HTTP multi-threadé, une base de données SQLite transactionnelle et une interface web réactive (Point de Vente, Direction, Clients & Ordonnances, Rappels SMS, Stocks, Pointage du Personnel, Vidéosurveillance).

---

## 🌐 Déploiement Cloud 100% Gratuit sur le Web

Vous pouvez héberger **PharmaClair** gratuitement 24h/24 sur le Cloud afin qu'il soit accessible depuis n'importe quel ordinateur, tablette ou smartphone sans dépendre de votre machine locale.

### Option 1 : Déploiement en 1 Clic sur Render (Recommandé)
1. Cliquez sur le bouton ci-dessus ou sur ce lien : **[Déployer sur Render](https://render.com/deploy?repo=https://github.com/jfokou/Pharmaclair)**
2. Connectez-vous avec votre compte GitHub.
3. Donnez un nom à votre application (ex: `pharmaclair-officine`).
4. Cliquez sur **Apply** / **Create Web Service**.
5. Votre application sera déployée et disposera d'une URL publique permanente : `https://pharmaclair-officine.onrender.com` !

### Option 2 : Déploiement sur Railway ou Koyeb
- **Railway** : Nouveau projet ➔ *Deploy from GitHub repo* ➔ Sélectionner `jfokou/Pharmaclair`. Railway détecte automatiquement le `Procfile`.
- **Koyeb** : Créer un service ➔ *GitHub* ➔ Sélectionner `jfokou/Pharmaclair` ➔ Détection automatique du `Dockerfile`.

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
