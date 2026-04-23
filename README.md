# 🛡️ Sentinel-Health : Audit Systeme Linux

## -------- Partie A - Présentation -------- 
**SentinelAudit** est un outil d'automatisation d'**audit système** et de surveillance d'intégrité pour serveurs/client Linux. Développé en **Python**, il permet de **surveiller** la santé matérielle, l'**état** des services critiques et de **détecter** des dérives de configuration ou des modifications suspectes sur des fichiers sensibles.

Le script permet d'envoyer une **alerte de manière automatique** sur le **serveur Discord** avec le **statut** des alertes audités. 

## Sommaire 

1. [Partie A - Presentation](#---------partie-a---présentation---------)
2. [Partie B - Fonctionnalités](#---------partie-b---fonctionnalités---------)
3. [Partie C - Installation](#---------partie-d-installation---------)
4. [Partie D - Structuration-depot](#---------partie-c-structuration-depot---------)
5. [Partie E - Automatisation-Crontab](#---------partie-e-automatisation-crontab---------)
6. [Partie F - Guide de Réponse aux Incidents](#️-guide-de-réponse-aux-incidents-incident-response)


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

##  -------- Partie D. Installation -------- 

1. **Cloner le dépôt :**
```bash
git clone [url depot]
cd [name_projet]
```

2. **Configuration :**
- Éditez le fichier `/data/security_baseline.csv` pour définir vos politiques de sécurité. 
- Créez un fichier `.env` à la racine sur le modèle suivant :          
```DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/xxxx```

## -------- Partie E. Automatisation (Crontab) -------- 
Pour une surveillance continue, il est recommandé d'ajouter le script à la crontab de l'utilisateur root :
```bash
sudo crontab -e
```
Ajoutez la ligne suivante pour un audit toutes les heures :
- ```0 * * * * /usr/bin/python3 /chemin/vers/audit.py```

## -------- Partie F. Technologies utilisées -------- 
* **Langage :** Python 3.x
* **Librairies :** python-dotenv, shutil, subprocess, psutil, os, time, csv, pwd, stat, json, requests, datetime
* **OS :** Linux (Debian/Ubuntu recommandé)

---
---
## 🛠️ Guide de Réponse aux Incidents (Incident Response)
L'intérêt de cet outil réside dans sa capacité à détecter des changements en temps réel. Si vous recevez une alerte critique concernant une modification de fichiers système (/etc, /bin, /sbin), voici la procédure d'investigation préconisée :

### 🔍 Étape 1 : Levée de doute (Mises à jour ou Action humaine ?)
Avant de conclure à une intrusion, il faut vérifier si le changement ne provient pas d'une tâche d'administration légitime ou d'une mise à jour automatique du système.

#### Vérifier les mises à jour système récentes :

```
Bash
# Remplacez la date par la date du jour
grep "install " /var/log/dpkg.log | grep "$(date +%Y-%m-%d)"
```
*Si des paquets ont été installés à l'heure de l'alerte, il s'agit probablement d'une mise à jour automatique (unattended-upgrades).*

#### Vérifier l'historique des commandes :

```
Bash
history | tail -n 50
```
*Vérifiez si vous (ou un autre administrateur) n'avez pas lancé une commande dont les effets auraient pu être différés.*

### 🛡️ Étape 2 : Analyse approfondie des modifications
Si aucune mise à jour n'est en cours, il faut identifier précisément quels fichiers ont été touchés. Une attention particulière doit être portée au dossier **/etc/pam.d/** (gestion de l'authentification).

### Lister les fichiers modifiés dans les dernières 60 minutes :

```
Bash
sudo find /etc /bin /sbin -mmin -60 -ls
```
**Alerte Rouge** : Si des fichiers comme **/etc/passwd, /etc/shadow ou des binaires critiques (ls, ps, login)** apparaissent dans la liste sans raison valable, le système doit être considéré comme **compromis**.

### 🕵️ Étape 3 : Audit des accès et connexions actives
Si une modification malveillante est suspectée, l'attaquant est peut-être encore présent sur la machine.

#### Vérifier les utilisateurs connectés :

```
Bash
who
# ou
w
```

#### Analyser les connexions réseau établies :

```
Bash
sudo ss -tunap | grep ESTAB
```
**Cherchez** des adresses IP inconnues, particulièrement celles connectées sur le port 22 (SSH) ou via des processus suspects.

## Conclusion de la démarche
Cette procédure permet de transformer une simple alerte de script en une véritable action de défense. L'utilisation de ce script permet de réduire drastiquement le MTTD (Mean Time To Detect), point crucial dans la survie d'une infrastructure face à une cyberattaque.

---
## Licence
Ce projet est sous licence **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**.
Toute utilisation commerciale est strictement interdite sans autorisation préalable. Consultez le fichier [LICENSE](./LICENSE) pour plus de détails.


---
- **Date** : 19/04/2026 
- **Auteur** : Alexis Rousseau - **Ingénieur | Administrateur systeme réseau & cybersécurité**