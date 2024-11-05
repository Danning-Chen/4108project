def s_box(input):
    """
    Applies the s-box to a 4-bit input given as a 4 bit decimal integer.

    :param input: a 4-bit decimal integer
    :return: a 4-bit binary integer as a list of binary digits.
    """
    s_box_binary = [
        [0, 1, 0, 1],  # 0x5
        [0, 0, 1, 1],  # 0x3
        [1, 0, 1, 0],  # 0xA
        [0, 0, 0, 1],  # 0x1
        [1, 1, 1, 0],  # 0xE
        [1, 1, 0, 1],  # 0xD
        [0, 0, 1, 0],  # 0x2
        [1, 0, 0, 1],  # 0x9
        [0, 1, 1, 0],  # 0x6
        [1, 1, 1, 1],  # 0xF
        [1, 1, 0, 0],  # 0xC
        [0, 1, 1, 1],  # 0x7
        [1, 0, 1, 1],  # 0xB
        [1, 0, 0, 0],  # 0x8
        [0, 0, 0, 0],  # 0x0
        [0, 1, 0, 0]   # 0x4
    ]

    return s_box_binary[input]

def permute(input):
    """
    Applies the permutation step to a 16-bit binary integer given as input.

    :param input: a list of lists: 16 bits in lists of 4 bits.
    :return: a list of four 4-bit hex integers that form the permuted 16-bit integer
    """
    permutation_table = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
    combined_input = [item for sublist in input for item in sublist]
    permuted = [0] * 16
    for i in range(16):
        permuted[permutation_table[i]] = combined_input[i]
    
    permuted_as_int = []
    for i in range(0, len(permuted), 4):
        permuted_as_int.append(binary_to_int(permuted[i:i+4]))
    
    return permuted_as_int

def key_mix(input, round_key):
    """
    Mixes the round key to the input given as a list of 4 4-bit decimal integers

    :param input: a list of 4 4-bit decimal integers.
    :param round_key: the round key given as a hexadecimal string 
    :return: a lsit of 4 4-bit decimal integers mixed with the round key
    """
    divided_key = [(round_key >> 12) & 0xF,
                   (round_key >> 8) & 0xF,
                   (round_key >> 4) & 0xF,
                   round_key & 0xF]
    
    output = []
    for i in range(4):
        output.append(input[i] ^ divided_key[i])
    
    return output

def spn(plaintext, round_keys):
    """
    Implements a 4-round Substitution-Permutation Network

    :param plaintext: a 16-bit hexadecimal
    :param round_keys: a list of 5 16-bit hexadecimal strings to be used as round keys for the SPN
    :return: the ciphertext
    """
    current_input = process_plaintext(plaintext)
    for i in range(3):
        mixed = key_mix(current_input, round_keys[i])
        subbed = []
        for nibble in mixed:
            subbed.append(s_box(nibble))
        current_input = permute(subbed)
    
    final_sub = []
    for nibble in key_mix(current_input, round_keys[3]):
        final_sub.append(binary_to_int(s_box(nibble)))
    
    ciphertext = process_ciphertext(key_mix(final_sub, round_keys[4]))
    return ciphertext
    
        
def binary_to_int(binary):
    """
    Helper function that converts a 4-bit binary integer to hexadecimal

    :param binary: a list of 4 binary digits representing a 4-bit binary integer
    :return: an integer
    """
    return int("".join(map(str, binary)), 2)

def process_plaintext(plaintext):
    """
    Helper function to convert the 16-bit hexadecimal string into a list of 4 decimal integers

    :param plaintext: a 16-bit hexadecimal string
    :return: a list of 4 decimal integers
    """
    nibbles = [(plaintext >> (4 * i)) & 0xF for i in range(4)]

    # The nibbles are in reverse order, so reverse them
    nibbles.reverse()
    return nibbles

def process_ciphertext(ciphertext):
    """
    Helper function to convert a list of 4 decimal integers into a hexadecimal string

    :param plaintext: a list of 4 decimal integers
    :return: a hexadecimal string
    """
    hex_value = sum(nibble << (4 * i) for i, nibble in enumerate(reversed(ciphertext)))

    # Convert the integer to hexadecimal
    return hex(hex_value)