import random
import math

def ecc_encode_repetition(m, lam, rep_factor=4096):
    m_bits = [(m >> i) & 1 for i in range(lam)]
    encoded_bits = []
    for bit in m_bits:
        encoded_bits.extend([bit] * rep_factor)
    encoded_int = int(''.join(map(str, encoded_bits[::-1])), 2)
    return encoded_int

def ecc_decode_repetition(raw, lam, rep_factor=4096):
    total_bits = lam * rep_factor
    raw_bits = bin(raw)[2:].zfill(total_bits)[-total_bits:]
    decoded_bits = []
    for i in range(0, total_bits, rep_factor):
        chunk = raw_bits[i:i+rep_factor]
        ones = chunk.count('1')
        decoded_bits.append('1' if ones > rep_factor // 2 else '0')
    decoded_int = int(''.join(decoded_bits), 2)
    return decoded_int

def random_nbit_weight(n, h):
    positions = random.sample(range(n), h)
    value = 0
    for pos in positions:
        value |= (1 << pos)
    return value

def keygen(n, h):
    assert 16*h*h >= n > 10*h*h, "Parameter conditions not satisfied."
    M_n = 2**n - 1

    F = random_nbit_weight(n, h)
    G = random_nbit_weight(n, h)
    R = random.getrandbits(n)

    T = ((F * R) + G ) % M_n
    pk = (R, T)
    sk = F

    return pk, sk

def H_oracle(n, h, seed):
    random.seed(seed)
    positions = random.sample(range(n), h)
    value = 0
    for pos in positions:
        value |= (1 << pos)
    return value



def encapsulate(pk, n, h, lam):
    R, T = pk
    M_n = 2**n - 1

    K = random.getrandbits(lam)
    A = H_oracle(n, h, str(K) + "H1")
    B1 = H_oracle(n, h, str(K) + "H2")
    B2 = H_oracle(n, h, str(K) + "H3")

    Em = ecc_encode_repetition(K, lam)

    C1 = (A * R + B1) % M_n
    
    C2 = (((A * T) + B2) % M_n ) ^ Em

    return (C1, C2), K

def decapsulate(sk, pk, ciphertext, n, h, lam):
    R, T = pk
    C1, C2 = ciphertext
    M_n = 2**n - 1

    raw = (sk * C1) % M_n
    K_prime = ecc_decode_repetition(C2 ^ raw, lam)

    A_prime = H_oracle(n, h, str(K_prime) + "H1")
    B1_prime = H_oracle(n, h, str(K_prime) + "H2")
    B2_prime = H_oracle(n, h, str(K_prime) + "H3")

    C1_prime = (A_prime * R + B1_prime) % M_n
    C2_prime = ecc_encode_repetition(K_prime, lam) ^ ((A_prime * T + B2_prime) % M_n)

    if (C1, C2) == (C1_prime, C2_prime):
        return K_prime
    else:
        return None



#----------Crendal------------------


def keygen_crendal(n, h, c):
    M_nc = 2**n - c
    assert 16*h*h >= n > 10*h*h, "Parameter conditions not satisfied."

    F = random_nbit_weight(n, h)
    while F > M_nc:
        F = random_nbit_weight(n, h)
    G = random_nbit_weight(n, h)
    while G > M_nc:
        G = random_nbit_weight(n, h)
    R = random.randrange(0, M_nc)

    T = ((F * R) + G ) % M_nc
    pk = (R, T)
    sk = F

    return pk, sk

def encapsulate_crendal(pk, n, h, lam, c):
    M_nc = 2**n - c

    K = random.getrandbits(lam)
    A = H_oracle(n, h, str(K) + "H1")
    B1 = H_oracle(n, h, str(K) + "H2")
    B2 = H_oracle(n, h, str(K) + "H3")

    Em = ecc_encode_repetition(K, lam)

    R, T = pk
    C1 = ((A * R) + B1) % M_nc
    C2 = (((A * T) + B2) % M_nc) ^ Em

    return (C1, C2), K

def decapsulate_crendal(sk, pk, ciphertext, n, h, lam, c):
    M_nc = 2**n - c
    C1, C2 = ciphertext
    F = sk
    R, T = pk

    raw = (sk * C1) % M_nc
    K_prime = ecc_decode_repetition(C2 ^ raw, lam)

    A_prime = H_oracle(n, h, str(K_prime) + "H1")
    B1_prime = H_oracle(n, h, str(K_prime) + "H2")
    B2_prime = H_oracle(n, h, str(K_prime) + "H3")

    C1_prime = (A_prime * R + B1_prime) % M_nc
    C2_prime = ecc_encode_repetition(K_prime, lam) ^ (((A_prime * T) + B2_prime) % M_nc)

    if (C1, C2) == (C1_prime, C2_prime):
        return K_prime
    else:
        return None

#--------GenMersenne-----------

def keygen_genmersenne(n, m, h):
    M_nm = 2**n - 2**m - 1
    assert 16*h*h >= n > 10*h*h, "Parameter conditions not satisfied."

    F = random_nbit_weight(n, h)
    while F > M_nm:
        F = random_nbit_weight(n, h)
    G = random_nbit_weight(n, h)
    while G > M_nm:
        G = random_nbit_weight(n, h)
    R = random.randrange(0, M_nm)

    T = ((F * R) + G ) % M_nm
    pk = (R, T)
    sk = F

    return pk, sk

def encapsulate_genmersenne(pk, n, m_param, h, lam):
    M_nm = 2**n - 2**m_param - 1

    K = random.getrandbits(lam)
    A = H_oracle(n, h, str(K) + "H1")
    B1 = H_oracle(n, h, str(K) + "H2")
    B2 = H_oracle(n, h, str(K) + "H3")

    Em = ecc_encode_repetition(K, lam)

    R, T = pk
    C1 = ((A * R) + B1) % M_nm
    C2 = (((A * T) + B2) % M_nm) ^ Em

    return (C1, C2), K

def decapsulate_genmersenne(sk, pk, ciphertext, n, m_param, h, lam):
    M_nm = 2**n - 2**m_param - 1
    C1, C2 = ciphertext
    F = sk
    R, T = pk

    raw = (sk * C1) % M_nm
    K_prime = ecc_decode_repetition(C2 ^ raw, lam)

    A_prime = H_oracle(n, h, str(K_prime) + "H1")
    B1_prime = H_oracle(n, h, str(K_prime) + "H2")
    B2_prime = H_oracle(n, h, str(K_prime) + "H3")

    C1_prime = (A_prime * R + B1_prime) % M_nm
    C2_prime = ecc_encode_repetition(K_prime, lam) ^ (((A_prime * T) + B2_prime) % M_nm)

    if (C1, C2) == (C1_prime, C2_prime):
        return K_prime
    else:
        return None

# Funclion to test repetition codes parameters

def error_test(n=11213, h=32, lam=32, n_tests=100, c=7713, m=9953):
    failures = 0
    for i in range(n_tests):
        pk, sk = keygen_crendal(n, h, c)
        (C1, C2), message = encapsulate_crendal(pk, n, h, lam, c)
        dec = decapsulate_crendal(sk, pk, (C1, C2), n, h, lam, c)
        # pk, sk = keygen(n, h)
        # (C1, C2), message = encapsulate(pk, n, h, lam)
        # dec = decapsulate(sk, pk, (C1, C2), n, h, lam)
        if dec != message:
            failures += 1
            diff = message ^ (dec if dec is not None else 0)
            bit_diff_count = bin(diff).count('1')
            print(f"Test {i+1}: Error! Bits different: {bit_diff_count}")
            differing_positions = [j for j in range(lam) if ((message >> j) & 1) != ((dec if dec is not None else 0) >> j) & 1]
            print(f"Different bit positions: {differing_positions}")
        else:
            print("Decryption is correct")
    print(f"Total failures: {failures} out of {n_tests}")
    if failures == 0:
        print("Success: All decryptions were correct.")
    else:
        print("Error: Some decryptions failed.")

def to_bitstring(val, length):
    return format(val, f'0{length}b')


def write_c1_c2(
    messages_standard, messages_crendal, messages_genmersenne,
    n=11213, h=33, lam=33, c=7713, m=9953, target_size_bits=16_000_000
):
    # Standard AJPS-KEM
    for idx, message in enumerate(messages_standard):
        # C1
        with open(f'data/ajps_kem/standard_C1_msg{idx}_{message}.e', 'w') as f1:
            current_bits = 0
            while current_bits < target_size_bits:
                pk, _ = keygen(n, h)
                (C1, C2), _ = encapsulate(pk, n, h, lam)
                bitstring = to_bitstring(C1, n)
                to_write = bitstring[: min(len(bitstring), target_size_bits - current_bits)]
                f1.write(to_write)
                current_bits += len(to_write)
        # C2
        with open(f'data/ajps_kem/standard_C2_msg{idx}_{message}.e', 'w') as f2:
            current_bits = 0
            while current_bits < target_size_bits:
                pk, _ = keygen(n, h)
                (C1, C2), _ = encapsulate(pk, n, h, lam)
                bitstring = to_bitstring(C2, n)
                to_write = bitstring[: min(len(bitstring), target_size_bits - current_bits)]
                f2.write(to_write)
                current_bits += len(to_write)

    # Crendal
    for idx, message in enumerate(messages_crendal):
        # C1
        with open(f'data/ajps_kem/crendal_C1_msg{idx}_{message}.e', 'w') as f1:
            current_bits = 0
            while current_bits < target_size_bits:
                pk, _ = keygen_crendal(n, h, c)
                (C1, C2), _ = encapsulate_crendal(pk, n, h, lam, c)
                bitstring = to_bitstring(C1, n)
                to_write = bitstring[: min(len(bitstring), target_size_bits - current_bits)]
                f1.write(to_write)
                current_bits += len(to_write)
        # C2
        with open(f'data/ajps_kem/crendal_C2_msg{idx}_{message}.e', 'w') as f2:
            current_bits = 0
            while current_bits < target_size_bits:
                pk, _ = keygen_crendal(n, h, c)
                (C1, C2), _ = encapsulate_crendal(pk, n, h, lam, c)
                bitstring = to_bitstring(C2, n)
                to_write = bitstring[: min(len(bitstring), target_size_bits - current_bits)]
                f2.write(to_write)
                current_bits += len(to_write)

    # GenMersenne
    for idx, message in enumerate(messages_genmersenne):
        # C1
        with open(f'data/ajps_kem/genmersenne_C1_msg{idx}_{message}.e', 'w') as f1:
            current_bits = 0
            while current_bits < target_size_bits:
                pk, _ = keygen_genmersenne(n, m, h)
                (C1, C2), _ = encapsulate_genmersenne(pk, n, m, h, lam)
                bitstring = to_bitstring(C1, n)
                to_write = bitstring[: min(len(bitstring), target_size_bits - current_bits)]
                f1.write(to_write)
                current_bits += len(to_write)
        # C2
        with open(f'data/ajps_kem/genmersenne_C2_msg{idx}_{message}.e', 'w') as f2:
            current_bits = 0
            while current_bits < target_size_bits:
                pk, _ = keygen_genmersenne(n, m, h)
                (C1, C2), _ = encapsulate_genmersenne(pk, n, m, h, lam)
                bitstring = to_bitstring(C2, n)
                to_write = bitstring[: min(len(bitstring), target_size_bits - current_bits)]
                f2.write(to_write)
                current_bits += len(to_write)

# if __name__ == "__main__":
#     messages_standard = [0, 14022004, 2**33-1]
#     messages_crendal = [0, 14022004, 2**33-1]
#     messages_genmersenne = [0, 14022004, 2**33-1]

#     write_c1_c2(
#         messages_standard, messages_crendal, messages_genmersenne
#     )

error_test()
