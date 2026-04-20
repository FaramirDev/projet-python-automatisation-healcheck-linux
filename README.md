# 🛡️ Automatisation Python - SentinelAudit - Linux

## -------- Partie A - Présentation -------- 
**SentinelAudit** est un outil d'automatisation d'**audit système** et de surveillance d'intégrité pour serveurs/client Linux. Développé en **Python**, il permet de **surveiller** la santé matérielle, l'**état** des services critiques et de **détecter** des dérives de configuration ou des modifications suspectes sur des fichiers sensibles.

Le script permet d'envoyer une **alerte de manière automatique** sur le **serveur Discord** avec le **statut** des alertes audités. 

##  -------- Partie B - Fonctionnalités -------- 

### **1. Audit Système :** 
**Analyse** de l'utilisation disque, monitoring de la RAM et des processus les plus gourmands. Basé sur **3 niveaux** de statut défini par des niveaux de seuil pour l'ensemble de l'audit :

- 🟢 **Vert** Statut : **Conforme** 
- 🟠 **Orange** Statut : **Warning** 
- 🔴 **Rouge** Statut : **Critique**

### **2. Surveillance de Services :** 
**2.1. Vérification** de l'état des **services** **critiques** (SSH, Pare-feu, etc.).

**2.2. HIDS (Host-based Intrusion Detection) :**

1. **Vérification** des **permissions** et des **propriétaires** des fichiers sensibles (*/etc/shadow, /etc/sudoers, etc.*) via un **référentiel CSV**.

![capture referentiel csv](./captures/referentiel_csv.png)

2. **Surveillance** des **dates** de modification et d'accès récents.

### **3. Alerting & Logging :**

3. **Remontée** d'alertes en temps réel via **Webhook Discord**.
    
![capture remonte discrod](./captures/output_discord_01.png)

4. Permet de **suivre** l'Alerte **directement** sur Telephone.
    
![capture remonte android](./captures/android_discord.png)

5. **Génération** de **rapports d'audit** structurés au format **JSON** pour l'historisation.

![capture rapport json 01](./captures/output_json_01.png)
![capture rapport json 02](./captures/output_json_02.png)

6. **Log** du Rapport dans la **console** egalement. 

![capture rapport console 01](./captures/output_console_01.png)
![capture rapport console 01](./captures/output_console_02.png)
![capture rapport console 01](./captures/output_console_03.png)

7. **Sécurité :** Gestion des secrets via variables d'environnement (.env).

##  -------- Partie C. Structuration Depot --------  
```text
├── data/              # Folder contenant data >> security_baseline.csv
├── logs/              # Folder Output Actuel des LOG en Json
├── captures/          # captures Readme
├── main.py            # script d'Audit
└── README.md
```

##  -------- Partie C. Installation -------- 

1. **Cloner le dépôt :**
```bash
git clone [url depot]
cd [name_projet]
```

2. **Configuration :**
- Éditez le fichier `/data/security_baseline.csv` pour définir vos politiques de sécurité. 
- Créez un fichier `.env` à la racine sur le modèle suivant :          
```DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/xxxx```

## -------- Partie D. Automatisation (Crontab) -------- 
Pour une surveillance continue, il est recommandé d'ajouter le script à la crontab de l'utilisateur root :
```bash
sudo crontab -e
```
Ajoutez la ligne suivante pour un audit toutes les heures :
- ```0 * * * * /usr/bin/python3 /chemin/vers/audit.py```

## -------- Partie E. Technologies utilisées -------- 
* **Langage :** Python 3.x
* **Librairies :** python-dotenv, shutil, subprocess, psutil, os, time, csv, pwd, stat, json, requests, datetime
* **OS :** Linux (Debian/Ubuntu recommandé)

---
- **Date** : 19/04/2026 
- **Auteur** : Alexis Rousseau - **Administrateur systeme réseau & cybersécurité**