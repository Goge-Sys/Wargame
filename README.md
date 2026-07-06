# Wargame — Reverse Engineering Challenge

> Challenge réalisé dans le cadre du module Wargame de l'ESD Cybersecurity Academy

## Présentation

Ce projet présente la conception et la résolution d'un challenge de type **Reverse Engineering** 
sur une machine Debian 13.

L'objectif pour le joueur : analyser un binaire ELF 64 bits compilé en C, 
comprendre son algorithme de vérification, et retrouver le mot de passe permettant 
d'élever ses privilèges jusqu'au compte root.

## Concept du challenge

Le binaire `challenge` implémente un système de vérification de mot de passe 
basé sur un double XOR :

- Une **clé statique** de 14 octets, stockée obfusquée dans le binaire (XOR 0x01)
- Un **secret dynamique** de 16 octets, stocké dans `/root/.secret` 
  (inaccessible directement par le joueur)
- Un **TARGET** de 16 octets codé en dur dans le binaire

La vérification suit l'équation :
result[i] = input[i] XOR key[i % 14] XOR secret[i]

Si `result == TARGET` → accès autorisé.

## Reproduire le challenge

### Prérequis
- VirtualBox
- Une ISO Debian 13
- gcc, python3, vim

### 1 — Créer la VM
- Type : Linux / Debian 64-bit
- RAM : 1024 Mo minimum
- Disque : VMDK
- Réseau : Bridge

### 2 — Créer le compte joueur
```bash
adduser administrateur
# Mot de passe au choix, ce sont les creds que le joueur utilisera
```

### 3 — Générer le secret
```bash
python3 -c "
import random
secret = bytes([random.randint(1,255) for _ in range(16)])
with open('/root/.secret', 'wb') as f:
    f.write(secret)
"
chmod 600 /root/.secret
chown root:root /root/.secret
```

### 4 — Générer le TARGET
```bash
python3 -c "
key = 'ESDw4rg4me2026'
password = 'VOTRE_MOT_DE_PASSE_ROOT'  # à choisir, 16 caractères
with open('/root/.secret', 'rb') as f:
    secret = f.read(16)
result = bytes([(ord(password[i]) ^ ord(key[i % len(key)])) ^ secret[i] for i in range(len(password))])
print(', '.join(f'0x{b:02x}' for b in result))
"
```

Colle les valeurs obtenues dans `TARGET[]` du `challenge.c`.

### 5 — Compiler et installer
```bash
gcc -O2 -s challenge.c -o /home/administrateur/challenge
chown root:root /home/administrateur/challenge
chmod 4755 /home/administrateur/challenge
```

### 6 — Autoriser gdb en sudo
```bash
/usr/sbin/visudo
# Ajouter :
administrateur ALL=(ALL) NOPASSWD: /usr/bin/gdb
```

### 7 — Créer le flag
```bash
echo "{VOTRE_FLAG}" > /root/flag.txt
chmod 600 /root/flag.txt
chown root:root /root/flag.txt
```

## Outils nécessaires pour résoudre

- `strings` - analyse statique basique
- `Ghidra` - décompilation et analyse du code
- `gdb` - analyse dynamique pour récupérer le secret en mémoire
- `Python 3` - script d'inversion du XOR

## Chemin de résolution

SSH (compte administrateur)
→ Découverte du binaire SUID
→ strings / file
→ Ghidra : analyse de l'algorithme
→ sudo gdb : interception du secret en mémoire
→ Python : inversion XOR → mot de passe
→ su root → cat /root/flag.txt

## Fichiers

| Fichier | Description |
|--------|-------------|
| `src/challenge.c` | Code source du crackme (valeurs anonymisées) |
| `solve/solve.py` | Script Python de résolution |
| `writeup/writeup.md` | Write Up complet avec explications |

 [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) ![C](https://img.shields.io/badge/language-C-blue) ![Python](https://img.shields.io/badge/script-Python3-green) ![Debian](https://img.shields.io/badge/platform-Debian%2013-red)
