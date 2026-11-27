# ℞ PharmaClair — Architecture Enterprise SaaS, Sécurité & Isolation Multi-Tenant

Ce document décrit l'architecture de production de **PharmaClair Enterprise SaaS** conçue pour garantir la confidentialité absolue des données des officines clientes et de leurs patients.

---

## 1. Principes Fondamentaux de Confidentialité & Séparation

| Environnement | Route | Rôles Autorisés | Accès Autorisé | Accès Strictement Interdit |
| :--- | :--- | :--- | :--- | :--- |
| **Plateforme SaaS** | `/platform-admin` | `superadmin`, `sales_rep`, `support` | Noms commerciaux, villes, plans, factures SaaS, MRR, ARR, CRM prospects, tickets support masqués (PII redactées), santé cloud. | **ZÉRO accès** aux ventes officinales, patients, ordonnances, stocks, lots, marges, dépenses, caisses, caméras ou audits internes. |
| **Espace Officine** | `/workspace` | `owner`, `pharmacist`, `branch_manager`, `cashier`, `stock`, `accountant`, `auditor` | Uniquement les données appartenant à leur propre `pharmacy_id` (et `branch_id` assigné). | **ZÉRO accès** aux données des autres pharmacies et aux écrans d'administration plateforme. |

---

## 2. Matrice des Permissions Officinales (RBAC)

- **Titulaire (`owner`)** : Tous les droits sur son organisation (y compris Finances P&L, Paramètres, Succursales, Abonnement SasPay, Audit antifraude).
- **Pharmacien (`pharmacist`)** : Ventes, stocks, réceptions, patients, ordonnances, validation clinique, approbations de retours.
- **Chef de Succursale (`branch_manager`)** : Opérations quotidiennes, caisse et rapports limités à sa succursale.
- **Caissier (`cashier`)** : Point de vente, ses propres ventes, clôture de caisse. *Ne peut voir ni les coûts d'achat (COGS), ni les marges, ni les bilans financiers globaux.*
- **Magasinier (`stock`)** : Réceptions fournisseurs, gestion des lots FEFO, inventaires physiques, commandes d'achat.
- **Comptable (`accountant`)** : Compte de résultat (P&L), dépenses, clôtures Z, exports comptables.
- **Auditeur (`auditor`)** : Journaux d'audit antifraude, détection d'anomalies, consultation financière.

---

## 3. Sauvegardes, Reprise Après Sinistre (DR) & Portabilité

- **Portabilité Tenant** : Chaque officine peut exporter ses propres données (`export_pharmacy_backup_json` et `export_sales_csv`) sans jamais inclure les données d'une autre pharmacie.
- **Objectifs (RTO / RPO)** :
  - **RPO** : < 24 heures (sauvegardes chiffrées automatiques quotidiennes) et **0 perte** pour les transactions synchronisées.
  - **RTO** : < 15 minutes par redéploiement conteneurisé Railway ou restauration SQLite WAL.
- **Limitation Hors-Ligne documentée** : Les ventes effectuées sur un terminal complètement déconnecté d'Internet ne sont présentes que dans l'IndexedDB de ce terminal jusqu'à sa reconnexion. Une perte physique du terminal avant synchronisation entraînerait la perte de ces événements non poussés.

---

## 4. Procédure de Rollback (Retour Arrière Sécurisé)

En cas d'incident après déploiement :
```bash
# Revenir au checkpoint stable précédent
git checkout checkpoint-pre-enterprise-saas
```
Les migrations SQLite étant additives (`ALTER TABLE ... ADD COLUMN`), aucune donnée existante n'est détruite lors d'un rollback.
