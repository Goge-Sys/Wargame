# Les trois éléments récupérés pendant le reverse :
TARGET = bytes([...])   # extrait via objdump depuis le binaire
KEY_OBF = bytes([...])  # lu dans Ghidra
SECRET = bytes.fromhex('...')  # intercepté via gdb au moment du fread

# Reconstruction de la clé
KEY = bytes([b ^ 0x01 for b in KEY_OBF])

# Inversion du XOR pour retrouver le mot de passe
password = bytes([TARGET[i] ^ KEY[i % 14] ^ SECRET[i] for i in range(16)])
print(f"Mot de passe : {password.decode()}")
