import random
import math
import matplotlib.pyplot as plt

def random_nbit_weight(n, h):
    positions = random.sample(range(n), h)
    value = 0
    for pos in positions:
        value |= (1 << pos)
    return value

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


def modinv(a, m):
    try:
        return pow(a, -1, m)
    except ValueError:
        raise Exception(f'Modular inverse does not exist for a = {a} mod {m}')


def keygen(n, h, lam):
    M = 2**n - 1
    
    # Verify parameter conditions
    if not (4 * (h ** 2) < n <= 16 * (h ** 2)):
        raise ValueError("Parameters must satisfy 4h^2 < n <= 16h^2")
    if math.comb(n, h) < 2**lam:
        raise ValueError("Parameters must satisfy C(n, h) >= 2^lambda")
    
    F = random_nbit_weight(n, h)
    G = random_nbit_weight(n, h)
    while math.gcd(G, M) != 1:
        G = random_nbit_weight(n, h)
        
    invG = modinv(G, M)
    H = (F * invG) % M
    pk = H
    sk = G
    return pk, sk

def encrypt(pk, b, n, h):
    if b not in (0, 1):
        raise ValueError("Message bit must be 0 or 1")
    
    M = 2**n - 1
    A = random_nbit_weight(n, h)
    B = random_nbit_weight(n, h)
    
    val = (A * pk + B) % M
    if b == 0:
        C = val
    else:  
        C = (-val) % M
    return C

def hamming_weight(x, n):
    bin_str = format(x, '0{}b'.format(n))
    return bin_str.count('1')

def decrypt(C, sk, n, h):
    M = 2**n - 1

    diff = (C * sk) % M
    D = hamming_weight(diff, n)
    
    if D <= 2 * (h ** 2):
        return 0
    elif D >= n - 2 * (h ** 2):
        return 1
    else:
        raise Exception("Decryption error (⊥): ambiguous result.")

# Variant 2: Cryptosystem using Crendal Numbers (M_nc = 2^n - c)

def keygen_crendal(n, h, lam, c):
    M_nc = 2**n - c
    
    if not (4 * (h ** 2) < n <= 16 * (h ** 2)):
        raise ValueError("Parameters must satisfy 4h^2 < n <= 16h^2")
    if math.comb(n, h) < 2**lam:
        raise ValueError("Parameters must satisfy C(n, h) >= 2^lambda")
    
    F = random_nbit_weight(n, h)
    while F > M_nc:
        F = random_nbit_weight(n, h)
    G = random_nbit_weight(n, h)
    while G > M_nc:
        G = random_nbit_weight(n, h)
    while math.gcd(G, M_nc) != 1:
        G = random_nbit_weight(n, h)
        
    invG = modinv(G, M_nc)
    H = (F * invG) % M_nc
    return H, G

def encrypt_crendal(pk, b, n, h, c):
    if b not in (0, 1):
        raise ValueError("Message bit must be 0 or 1")
    
    M_nc = 2**n - c
    
    A = random_nbit_weight(n, h)
    B = random_nbit_weight(n, h)

    while A > M_nc:
        A = random_nbit_weight(n, h)
    while B > M_nc:
        B = random_nbit_weight(n, h)
    
    C = ((A * pk) + (-1)**B) % M_nc
    return C

def decrypt_crendal(C, sk, n, h, c):
    M_nc = 2**n - c
    diff = (C - sk) % M_nc
    D = hamming_weight(diff, n)
    
    if D <= 2 * (h ** 2):
        return 0
    elif D >= n - 2 * (h ** 2):
        return 1
    else:
        raise Exception("Decryption error (⊥): ambiguous result.")

# Variant 3: Cryptosystem using Generalized Mersenne Numbers (M_nm = 2^n - 2^m - 1)

def keygen_genmersenne(n, m, h, lam):
    M_nm = 2**n - 2**m - 1
    
    if not (4 * (h ** 2) < n <= 16 * (h ** 2)):
        raise ValueError("Parameters must satisfy 4h^2 < n <= 16h^2")
    if math.comb(n, h) < 2**lam:
        raise ValueError("Parameters must satisfy C(n, h) >= 2^lambda")
    
    F = random_nbit_weight(n, h)
    while F > M_nm:
        F = random_nbit_weight(n, h)
    G = random_nbit_weight(n, h)
    while G > M_nm:
        G = random_nbit_weight(n, h)
    while math.gcd(G, M_nm) != 1:
        G = random_nbit_weight(n, h)
        
    invG = modinv(G, M_nm)
    H = (F * invG) % M_nm
    return H, G

def encrypt_genmersenne(pk, b, n, m, h):
    if b not in (0, 1):
        raise ValueError("Message bit must be 0 or 1")
    
    M_nm = 2**n - 2**m - 1
    
    A = random_nbit_weight(n, h)
    B = random_nbit_weight(n, h)

    while A > M_nm:
        A = random_nbit_weight(n, h)
    while B > M_nm:
        B = random_nbit_weight(n, h)
    
    C = ((A * pk) + (-1)**B) % M_nm
    return C

def decrypt_genmersenne(C, sk, n, m, h):
    M_nm = 2**n - 2**m - 1
    diff = (C - sk) % M_nm
    D = hamming_weight(diff, n)
    
    if D <= 2 * (h ** 2) + h * (2*m - 2):
        return 0
    elif D >= n - 2 * (h ** 2) - 1:
        return 1
    else:
        raise Exception("Decryption error (⊥): ambiguous result.")


def pk_to_bitstring(pk, length):
    return format(pk, f'0{length}b')

# Write newly generated bitstrings repeatedly to file until target size in bytes
def write_bits_to_file(filename, keygen_func, length, target_size_bytes=2 * 1024 * 1024, *args):
    with open(filename, 'w') as f:
        current_size = 0
        while current_size < target_size_bytes * 8:
            pk, _ = keygen_func(*args)
            bitstring = pk_to_bitstring(pk, length)
            remaining_bits = (target_size_bytes * 8) - current_size
            if len(bitstring) <= remaining_bits:
                f.write(bitstring)
                current_size += len(bitstring)
            else:
                f.write(bitstring[:remaining_bits])
                current_size += remaining_bits


def generate_pk_files():
    # Parameters
    n = 4253
    h = 32
    lam = 267
    m = 499
    c = 3981

    # Generate files by continuously generating new keys until size is met
    write_bits_to_file('ajps1standard_pk4253.e', keygen, n, 2 * 1024 * 1024, n, h, lam)
    write_bits_to_file('ajps1crendal_pk4253.e', keygen_crendal, n, 2 * 1024 * 1024, n, h, lam, c)
    write_bits_to_file('ajps1genmersenne_pk4253.e', keygen_genmersenne, n, 2 * 1024 * 1024, n, m, h, lam)


def generate_ciphertext_files():
    # Parameters
    n = 4253
    h = 32
    lam = 267
    m = 499
    c = 3981

    # Message bits to encrypt
    bits = [0, 1]
    
    for b in bits:
        # Standard
        with open(f'ajps1standard_ct{b}_pk4253test.e', 'w') as f:
            current_size = 0
            while current_size < 2 * 1024 * 1024 * 8:
                pk, sk = keygen(n, h, lam)
                ct = encrypt(pk, b, n, h)
                bitstring = pk_to_bitstring(ct, n)
                remaining_bits = (2 * 1024 * 1024 * 8) - current_size
                if len(bitstring) <= remaining_bits:
                    f.write(bitstring)
                    current_size += len(bitstring)
                else:
                    f.write(bitstring[:remaining_bits])
                    current_size += remaining_bits

        # Crendal
        with open(f'ajps1crendal_ct{b}_pk4253.e', 'w') as f:
            current_size = 0
            while current_size < 2 * 1024 * 1024 * 8:
                pk, sk = keygen_crendal(n, h, lam, c)
                ct = encrypt_crendal(pk, b, n, h, c)
                bitstring = pk_to_bitstring(ct, n)
                remaining_bits = (2 * 1024 * 1024 * 8) - current_size
                if len(bitstring) <= remaining_bits:
                    f.write(bitstring)
                    current_size += len(bitstring)
                else:
                    f.write(bitstring[:remaining_bits])
                    current_size += remaining_bits

        # GenMersenne
        with open(f'ajps1genmersenne_ct{b}_pk4253.e', 'w') as f:
            current_size = 0
            while current_size < 2 * 1024 * 1024 * 8:
                pk, sk = keygen_genmersenne(n, m, h, lam)
                ct = encrypt_genmersenne(pk, b, n, m, h)
                bitstring = pk_to_bitstring(ct, n)
                remaining_bits = (2 * 1024 * 1024 * 8) - current_size
                if len(bitstring) <= remaining_bits:
                    f.write(bitstring)
                    current_size += len(bitstring)
                else:
                    f.write(bitstring[:remaining_bits])
                    current_size += remaining_bits


def main():
   # generate_pk_files()
    generate_ciphertext_files()

main()