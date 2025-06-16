import random
import math

def ecc_encode_repetition(m, lam, rep_factor=2048):
    m_bits = [(m >> i) & 1 for i in range(lam)]
    encoded_bits = []
    for bit in m_bits:
        encoded_bits.extend([bit] * rep_factor)
    encoded_int = int(''.join(map(str, encoded_bits[::-1])), 2)
    return encoded_int

def ecc_decode_repetition(raw, lam, rep_factor=2048):
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

# Key Generation Function
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


# Encryption Function
def encrypt(pk, m, n, h, lam):
    R, T = pk
    M_n = 2**n - 1
    assert m.bit_length() <= lam, "Message too long"

    A = random_nbit_weight(n, h)
    B1 = random_nbit_weight(n, h)
    B2 = random_nbit_weight(n, h)

    Em = ecc_encode_repetition(m, lam)

    C1 = ((A * R) + B1) % M_n
    C2 = (((A * T) + B2) % M_n) ^ Em

    return (C1, C2)

# Decryption Function
def decrypt(sk, ciphertext, n, lam):
    C1, C2 = ciphertext
    M_n = 2**n - 1
    raw = ((sk * C1) % M_n) ^ C2

    m = ecc_decode_repetition(raw, lam)
    return m


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

def encrypt_crendal(pk, m, n, h, lam, c):
    M_nc = 2**n - c
    R, T = pk
    assert m.bit_length() <= lam, "Message too long"

    A = random_nbit_weight(n, h)
    while A > M_nc:
        A = random_nbit_weight(n, h)
    B1 = random_nbit_weight(n, h)
    while B1 > M_nc:
        B1 = random_nbit_weight(n, h)
    B2 = random_nbit_weight(n, h)
    while B2 > M_nc:
        B2 = random_nbit_weight(n, h)

    Em = ecc_encode_repetition(m, lam)

    C1 = ((A * R) + B1) % M_nc
    C2 = (((A * T) + B2) % M_nc) ^ Em

    return (C1, C2)

def decrypt_crendal(sk, ciphertext, n, lam, c):
    M_nc = 2**n - c
    C1, C2 = ciphertext

    raw = ((sk * C1) % M_nc) ^ C2

    m = ecc_decode_repetition(raw, lam)
    return m

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

def encrypt_genmersenne(pk, m, n, m_param, h, lam):
    M_nm = 2**n - 2**m_param - 1
    R, T = pk
    assert m.bit_length() <= lam, "Message too long"

    A = random_nbit_weight(n, h)
    while A > M_nm:
        A = random_nbit_weight(n, h)
    B1 = random_nbit_weight(n, h)
    while B1 > M_nm:
        B1 = random_nbit_weight(n, h)
    B2 = random_nbit_weight(n, h)
    while B2 > M_nm:
        B2 = random_nbit_weight(n, h)

    Em = ecc_encode_repetition(m, lam)

    C1 = ((A * R) + B1) % M_nm
    C2 = (((A * T) + B2) % M_nm) ^ Em

    return (C1, C2)

def decrypt_genmersenne(sk, ciphertext, n, m_param, lam):
    M_nm = 2**n - 2**m_param - 1
    C1, C2 = ciphertext

    raw = ((sk * C1) ^ C2) % M_nm

    m = ecc_decode_repetition(raw, lam)
    return m


def to_bitstring(val, length):
    return format(val, f'0{length}b')

def write_bits_to_file(filename, keygen_func, n, target_size_bits, *args):
    with open(filename, 'w') as f:
        current_bits = 0
        while current_bits < target_size_bits:
            pk, _ = keygen_func(*args)
            T = pk[1] 
            bitstring = to_bitstring(T, n)
            remaining_bits = target_size_bits - current_bits
            to_write = bitstring if len(bitstring) <= remaining_bits else bitstring[:remaining_bits]
            f.write(to_write)
            current_bits += len(to_write)

def write_bits_to_file(filename, keygen_func, length, target_size_bytes=2 * 1024 * 1024, *args):
    with open(filename, 'w') as f:
        current_size = 0
        while current_size < target_size_bytes * 8:
            pk, _ = keygen_func(*args)
            pk = pk[1]
            bitstring = to_bitstring(pk, length)
            remaining_bits = (target_size_bytes * 8) - current_size
            if len(bitstring) <= remaining_bits:
                f.write(bitstring)
                current_size += len(bitstring)
            else:
                f.write(bitstring[:remaining_bits])
                current_size += remaining_bits


def generate_pk_files():
    n = 11213
    c = 7713
    m = 9953
    h = lam = 33
    target_size_bits = 2_000_000

        # Standard
    write_bits_to_file(f'data/ajps2/T/standard_T_{n}.e', keygen, n, target_size_bits, n, h)
        # Crendal
    write_bits_to_file(f'data/ajps2/T/crendal_T_{n}.e', keygen_crendal, n, target_size_bits, n, h, c)
        # GenMersenne
    write_bits_to_file(f'data/ajps2/T/genmersenne_T_{n}.e', keygen_genmersenne, n, target_size_bits, n, m, h)


# Funclion to test repetition codes parameters
def error_test():

    n = 11213
    c = 7713
    m = 9953
    h = lam = 33

    n_tests = 100
    failures = 0

    for i in range(n_tests):
        pk, sk = keygen_crendal(n, h, c)
        message = random.getrandbits(lam)
        ciphertext = encrypt_crendal(pk, message, n, h, lam, c)
        decrypted_message = decrypt_crendal(sk, ciphertext, n, lam, c)
        if decrypted_message != message:
            failures += 1
            diff = message ^ decrypted_message
            bit_diff_count = bin(diff).count('1')
            print(f"Test {i+1}: Error! Bits different: {bit_diff_count}")
    
    print(f"Total failures: {failures} out of {n_tests}")
    if failures == 0:
        print("Success: All decryptions were correct.")
    else:
        print("Error: Some decryptions failed.")



def write_single_component_bits_to_file(filename, encrypt_func, keygen_func, message, n, h, lam, target_size_bits, component_idx, *key_args):
    with open(filename, 'w') as f:
        current_bits = 0
        while current_bits < target_size_bits:
            pk, _ = keygen_func(*key_args)
            if encrypt_func.__name__ == "encrypt":
                ct = encrypt_func(pk, message, n, h, lam)
            elif encrypt_func.__name__ == "encrypt_crendal":
                c = key_args[-1]
                ct = encrypt_func(pk, message, n, h, lam, c)
            elif encrypt_func.__name__ == "encrypt_genmersenne":
                m_param = key_args[1]
                ct = encrypt_func(pk, message, n, m_param, h, lam)
            else:
                raise ValueError("Unknown encrypt_func")
            component = [ct[0], ct[1]][component_idx]
            bitstring = to_bitstring(component, n)
            remaining_bits = target_size_bits - current_bits
            to_write = bitstring if len(bitstring) <= remaining_bits else bitstring[:remaining_bits]
            f.write(to_write)
            current_bits += len(to_write)



def generate_ciphertext(
    messages_standard, messages_crendal, messages_genmersenne
):
    n = 11213
    c = 7713
    m = 9953
    h = lam = 33
    target_size_bits = 16_000_000

    # Standard
    for idx, message in enumerate(messages_standard):
        write_single_component_bits_to_file(
            f'data/ajps2/C1/standard_C1_msg{idx}.e',
            encrypt, keygen, message, n, h, lam, target_size_bits, 0, n, h
        )
        write_single_component_bits_to_file(
            f'data/ajps2/C2/standard_C2_msg{idx}.e',
            encrypt, keygen, message, n, h, lam, target_size_bits, 1, n, h
        )

    # Crendal
    for idx, message in enumerate(messages_crendal):
        write_single_component_bits_to_file(
            f'data/ajps2/C1/crendal_C1_msg{idx}.e',
            encrypt_crendal, keygen_crendal, message, n, h, lam, target_size_bits, 0, n, h, c
        )
        write_single_component_bits_to_file(
            f'data/ajps2/C2/crendal_C2_msg{idx}.e',
            encrypt_crendal, keygen_crendal, message, n, h, lam, target_size_bits, 1, n, h, c
        )

    # GenMersenne
    for idx, message in enumerate(messages_genmersenne):
        write_single_component_bits_to_file(
            f'data/ajps2/C1/genmersenne_C1_msg{idx}.e',
            encrypt_genmersenne, keygen_genmersenne, message, n, h, lam, target_size_bits, 0, n, m, h
        )
        write_single_component_bits_to_file(
            f'data/ajps2/C2/genmersenne_C2_msg{idx}.e',
            encrypt_genmersenne, keygen_genmersenne, message, n, h, lam, target_size_bits, 1, n, m, h
        )

messages_standard = [0, 14022004, 2**33-1]
messages_crendal = [0, 14022004, 2**33-1]
messages_genmersenne = [0, 14022004, 2**33-1]

#generate_pk_files() 
#generate_ciphertext_files_for_messages_multi(messages_standard, messages_crendal, messages_genmersenne)
error_test()
