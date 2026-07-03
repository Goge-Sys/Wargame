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

## Outils nécessaires pour résoudre

- `strings` — analyse statique basique
- `Ghidra` — décompilation et analyse du code
- `gdb` — analyse dynamique pour récupérer le secret en mémoire
- `Python 3` — script d'inversion du XOR

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

 [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
