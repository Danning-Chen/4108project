from collections import Counter

# Parameters for the attack
TARGET_OUTPUT_DIFF = 0x0088

# Read ciphertext pairs from a file
def read_ciphertext_pairs(filename):
    ciphertext_pairs = []
    with open(filename, 'r') as file:
        for line in file:
            # Strip whitespace and split the line by comma
            parts = line.strip().split(',')
            # Convert each part to an integer (assuming they are in hex format)
            C1 = int(parts[0].strip(), 16)
            C2 = int(parts[1].strip(), 16)
            ciphertext_pairs.append((C1, C2))
    return ciphertext_pairs

# Define the inverse S-box function
def inverse_s_box(output):
    """
    Applies the inverse of the s-box to a 4-bit output.

    :param output: a 4-bit decimal integer (0-15)
    :return: a 4-bit integer representing the inverse S-box result
    """
    # Inverse S-box as a mapping based on the original S-box
    inverse_s_box_table = [
        0xE, 0x3, 0x6, 0x1, 0xF, 0x0, 0x8, 0xB,
        0xD, 0x7, 0x2, 0xC, 0x4, 0x9, 0xA, 0x5
    ]
    return inverse_s_box_table[output]

# Partial decryption function for the last round
def partial_decrypt_round_5(ciphertext, subkey_guess):
    """
    Partially decrypts the last round of the SPN cipher to reach the entrance of the 4th round.

    :param ciphertext: a 16-bit integer (ciphertext)
    :param subkey_guess: an 8-bit guess for the last byte of the 5th subkey
    :return: a 16-bit integer representing the state at the entrance of the 4th round
    """
    # Step 1: XOR the ciphertext with the guessed subkey (we assume we're only guessing the last byte here)
    # Extract the last byte (8 bits) of the ciphertext to apply the guess on
    mixed_state = ciphertext ^ (subkey_guess << 8)
    
    # Step 2: Apply the inverse S-box to each 4-bit nibble
    state = []
    for i in range(4):
        nibble = (mixed_state >> (4 * (3 - i))) & 0xF
        state.append(inverse_s_box(nibble))

    # Step 3: Convert state back to 16-bit integer form (skip permutation)
    decrypted_state = (state[0] << 12) | (state[1] << 8) | (state[2] << 4) | state[3]
    
    return decrypted_state


def differential_attack(ciphertext_pairs, num_trials=5):
    """
    Differential cryptanalysis function using provided ciphertext pairs, repeated for a specified number of trials.
    
    :param ciphertext_pairs: List of tuples with pairs of ciphertexts
    :param num_trials: Number of times to repeat the attack to improve reliability
    :return: Most likely last byte of the 5th subkey
    """
    # Counter to keep track of the frequency of each subkey guess
    subkey_guess_counts = Counter()

    # Repeat the process for a specified number of trials
    for _ in range(num_trials):
        # Step through each ciphertext pair
        for C1, C2 in ciphertext_pairs:
            # For each possible value of the last byte of the 5th subkey
            for subkey_guess in range(0x00, 0x100):
                # Partially decrypt C1 and C2 using the subkey guess
                partial_decrypt_C1 = partial_decrypt_round_5(C1, subkey_guess)
                partial_decrypt_C2 = partial_decrypt_round_5(C2, subkey_guess)

                # Check if the partial decryption result matches the target output difference
                if (partial_decrypt_C1 ^ partial_decrypt_C2) == TARGET_OUTPUT_DIFF:
                    subkey_guess_counts[subkey_guess] += 1

    # Find the subkey guess with the highest count
    if not subkey_guess_counts:
        print("No subkey guess produced the desired output difference.")
        return None

    most_likely_subkey = subkey_guess_counts.most_common(1)[0][0]
    print(f"Most likely last byte of the 5th subkey: {most_likely_subkey:02X}")
    print("Subkey guess counts:", subkey_guess_counts)
    return most_likely_subkey


# Example usage
ciphertext_pairs = read_ciphertext_pairs("ciphertext_pairs.txt")
most_likely_subkey = differential_attack(ciphertext_pairs)
