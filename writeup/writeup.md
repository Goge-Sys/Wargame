# Write Up — Reverse Engineering Challenge
 
## 1. Découverte du binaire
 
Une fois connecté avec le compte utilisateur, on liste le contenu du répertoire home :
 
```bash
user@VM:~$ ls -la
```
 
On remarque immédiatement deux choses importantes :
 
- Un binaire nommé `challenge`, appartenant à **root**
- Il possède le bit **SUID root** (`-rwsr-xr-x`), ce qui signifie qu'il s'exécute avec les droits root, même lancé par un utilisateur normal
On vérifie le type de fichier :
 
```bash
user@VM:~$ file challenge
```
 
C'est un binaire **ELF 64 bits, strippé** (sans symboles de debug).
 
---
 
## 2. Première analyse statique
 
On commence par extraire les chaînes de caractères lisibles du binaire :
 
```bash
user@VM:~$ strings challenge
```
 
On remarque plusieurs éléments intéressants :
 
- `/root/.secret` — le binaire lit un fichier secret appartenant à root
- `Mot de passe :` — le binaire demande un mot de passe
- `Mauvais mot de passe.` et `Acces autorise.`, deux chemins possibles.
Le fichier `/root/.secret` étant inaccessible directement :
 
```bash
user@VM:~$ cat /root/.secret
# cat: /root/.secret: Permission non accordée
```

 
Il va falloir analyser le binaire en profondeur pour comprendre comment il utilise ce fichier.
 
---
 
## 3. Analyse statique avec Ghidra
 
On ouvre le binaire dans **Ghidra**, on crée un nouveau projet, on importe le fichier et on lance l'analyse automatique.
 
On localise la fonction `main` dans le panneau **Symbol Tree**. Comme c'est un binaire strippé, il n'y a pas de fonction `main` à proprement parler — elle s'appelle `entry`. On double-clique ensuite sur `FUN_00101100` dans le pseudo-code à droite pour nous emmener dans la vraie fonction main.
 
L'analyse du code décompilé révèle les éléments suivants :
 
### 3.1 Lecture du fichier secret
 
Le programme ouvre `/root/.secret` et lit **16 octets** :
 
```c
__stream = fopen("/root/.secret", "rb");
fread(local_b8, 1, 0x10, __stream);
```
 
### 3.2 Reconstruction de la clé
 
Une clé de 14 octets est stockée **obfusquée** dans le binaire, et reconstituée au runtime via un XOR avec `0x01` :
 
```c
local_d8[0] = 0x44;
local_d8[1] = 0x52;
local_d8[2] = 0x45;
// ...
local_d8[0xc] = 0x33;
local_d8[0xd] = 0x37;
```
 
Puis chaque octet est XORé avec `0x01` :
 
```c
lVar2 = 0;
do {
    local_c8[lVar2] = local_d8[lVar2] ^ 1;
    lVar2 = lVar2 + 1;
} while (lVar2 != 0xe);
```
 
On peut reconstituer la clé réelle avec un script Python :
 
```python
KEY_OBF = bytes([0x44, 0x52, 0x45, ...])  # valeurs extraites de Ghidra
KEY = bytes([b ^ 0x01 for b in KEY_OBF])
print(KEY)
```
 
### 3.3 Vérification de la longueur
 
Le programme n'accepte que les mots de passe d'une longueur exacte de **16 caractères** :
 
```c
sVar4 = strlen((char *)local_98);
if (sVar4 == 0x10) {
    // ...
}
puts("Mauvais mot de passe.");
```
 
### 3.4 Calcul de la valeur de contrôle
 
Pour chaque caractère du mot de passe, le programme effectue un XOR entre :
- l'octet du secret (`local_b8`)
- l'octet du mot de passe utilisateur (`local_98`)
- l'octet de la clé reconstruite (`local_c8`)
```c
local_a8[uVar5] = local_b8[uVar5] ^ local_98[uVar5] ^
    local_c8[(int)uVar5 + (int)((uVar5 >> 1 & 0x7fffffff) / 7) * -0xe];
```
 
### 3.5 Comparaison avec la valeur cible
 
Le résultat est comparé à une constante (TARGET) stockée dans le binaire :
 
```c
iVar1 = memcmp(local_a8, &DAT_00102080, 0x10);
if (iVar1 == 0) {
    printf("Acces autorise. Mot de passe root: %s\n", local_98);
}
```
 
### 3.6 Équation finale
 
La condition de validation est :
 
```
secret[i] XOR password[i] XOR key[i % 14] = TARGET[i]
```
 
En isolant le mot de passe :
 
```
password[i] = TARGET[i] XOR secret[i] XOR key[i % 14]
```
 
---
 
## 4. Extraction du TARGET via objdump
 
On extrait les valeurs du TARGET depuis la section `.rodata` du binaire :
 
```bash
objdump -s -j .rodata challenge
```
 
---
 
## 5. Récupération du secret via gdb
 
Le seul élément manquant est le contenu de `/root/.secret`. Comme on ne peut pas le lire directement, on utilise `gdb` avec les droits sudo (configurés sur cette machine) pour intercepter sa valeur en mémoire au moment où le programme le lit.
 
```bash
user@VM:~$ sudo gdb ./challenge
```
 
On pose un point d'arrêt sur `fread` :
 
```
(gdb) break fread
(gdb) run
```
 
Le programme s'arrête au moment de l'appel à `fread`. On récupère l'adresse du buffer destination dans le registre `rdi` :
 
```
(gdb) info registers rdi
rdi   0x[ADRESSE]
```
 
On laisse `fread` se terminer puis on lit les 16 octets écrits à cette adresse :
 
```
(gdb) finish
(gdb) x/16bx 0x[ADRESSE]
0x[ADRESSE]: 0x??  0x??  0x??  0x??  0x??  0x??  0x??  0x??
             0x??  0x??  0x??  0x??  0x??  0x??  0x??  0x??
```
 
On convertit les octets en chaîne hexadécimale :
 
```bash
python3 -c "print(''.join(['??','??', ...]))"
```
 
---
 
## 6. Calcul du mot de passe
 
On dispose maintenant des trois éléments nécessaires :
 
| Élément | Source |
|---------|--------|
| TARGET | Extrait via `objdump` |
| KEY | Reconstruite depuis Ghidra (KEY_OBF XOR 0x01) |
| SECRET | Intercepté via `gdb` |
 
On écrit le script Python pour inverser le XOR et retrouver le mot de passe :
 
```python
TARGET = bytes([...])  # extrait via objdump
 
KEY_OBF = bytes([...])  # extrait via Ghidra
KEY = bytes([b ^ 0x01 for b in KEY_OBF])
 
secret = bytes.fromhex('[gdb result]')  # intercepté via gdb
 
password = bytes([TARGET[i] ^ KEY[i % 14] ^ secret[i] for i in range(16)])
print(password.decode())
```

---
 
## 7. Obtention du flag
 
On exécute le binaire avec le mot de passe trouvé :
 
```bash
user@VM:~$ ./challenge
Mot de passe : [mot_de_passe]
Acces autorise. Mot de passe root: [mot_de_passe]
```
 
On utilise ce mot de passe pour passer root et lire le flag :
 
```bash
user@VM:~$ su - root
Mot de passe : 
root@VM:~# cat /root/flag.txt
{FLAG}
```
