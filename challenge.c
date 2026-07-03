// challenge.c
// Challenge Wargame - ESD Cybersecurity Academy 2025-2026
// Reverse Engineering - Double XOR avec secret dynamique
//
// Compilation : gcc -O2 -s challenge.c -o challenge
// Installation : chown root:root challenge && chmod 4755 challenge

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

const int KEY_LEN = 14;
const int TARGET_LEN = 16;

// Valeur cible (anonymisée pour le dépôt public)
// Générée via : (password[i] XOR key[i%14]) XOR secret[i]
const unsigned char TARGET[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

int main(void) {
    // Lecture du secret dynamique (16 octets, accessible root uniquement)
    FILE *f = fopen("/root/.secret", "rb");
    if (!f) {
        puts("Erreur systeme.");
        return 1;
    }
    unsigned char secret[16];
    fread(secret, 1, 16, f);
    fclose(f);

    // Reconstruction de la clé au runtime
    // Stockée obfusquée (XOR 0x01) pour ne pas apparaître en clair dans strings
    const unsigned char KEY_OBF[] = {
        0x44, 0x52, 0x45, 0x76, 0x35, 0x73, 0x66, 0x35,
        0x6c, 0x64, 0x33, 0x31, 0x33, 0x37
    };
    unsigned char KEY[14];
    for (int i = 0; i < KEY_LEN; i++) {
        KEY[i] = KEY_OBF[i] ^ 0x01;
        // KEY_OBF XOR 0x01 → "ESDw4rg4me2026"
    }

    // Lecture du mot de passe utilisateur
    char input[128];
    printf("Mot de passe : ");
    if (!fgets(input, sizeof(input), stdin)) return 1;
    input[strcspn(input, "\n")] = 0;

    // Vérification de la longueur exacte
    int len = strlen(input);
    if (len != TARGET_LEN) {
        puts("Mauvais mot de passe.");
        return 1;
    }

    // Calcul : result[i] = input[i] XOR key[i%14] XOR secret[i]
    unsigned char result[16];
    for (int i = 0; i < len; i++) {
        result[i] = (input[i] ^ KEY[i % KEY_LEN]) ^ secret[i];
    }

    // Comparaison avec le TARGET
    if (memcmp(result, TARGET, 16) == 0) {
        printf("Acces autorise. Mot de passe root: %s\n", input);
    } else {
        puts("Mauvais mot de passe.");
    }

    return 0;
}
