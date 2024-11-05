import random
from spn import *

def generate_plaintext_pairs(input_difference, num_pairs=5000):
    ciphertext_pairs = []
    keys = [0x39cf, 0x13e7, 0x29a6, 0x24a8, 0x1f95]

    for _ in range(num_pairs):
        # Generate a random plaintext
        plaintext1 = random.randint(0, 0xFFFF)
        # Calculate the second plaintext using the input difference
        plaintext2 = plaintext1 ^ input_difference
        
        # Encrypt both plaintexts
        ciphertext1 = spn(plaintext1, keys)
        ciphertext2 = spn(plaintext2, keys)

        # Store the plaintext pair and their corresponding ciphertexts
        ciphertext_pairs.append((ciphertext1, ciphertext2))

    return ciphertext_pairs

def main():
    pairs = generate_plaintext_pairs(0x0d00)

    with open("ciphertext_pairs.txt", "w") as output_file:
        for pair in pairs:
            output_file.write(f"{pair[0]}, {pair[1]}\n")

if __name__ == "__main__":
    main()