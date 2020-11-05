import random
import math
import hashlib


def bits(n: int) -> int:
    cnt = 0
    while n:
        n = n // 2
        cnt += 1
    return cnt


def prime_test(n: int) -> bool:
    """
    A probabilistic prime test
    If n is composite, it may return True with a very small probability.
    If n is prime, it returns True.
    Please refer to the "Miller–Rabin test" section at https://en.wikipedia.org/wiki/Primality_test
    """
    assert n >= 2
    if n == 2:
        return True
    cnt = bits(n)
    d = n - 1
    s = 0
    while d & 1 == 0:
        d = d // 2
        s += 1
    if s == 0:
        # d is odd, n is even
        return False
    k = cnt // 2  # error probability <= 1 / 4^k ~= 1 / 2^bits
    random_upper_bound = n - 1
    for _ in range(k):
        a = random.randint(2, random_upper_bound)
        res = pow(a, d, n)
        if res == 1 or res == random_upper_bound:
            # maybe a prime, turn to next check
            continue
        for _ in range(s):
            if _ == s - 1:
                # composite
                return False
            res = pow(res, 2, n)
            if res == random_upper_bound:
                break
    return True


def generate_prime(nbits: int):
    # placeholder
    bits_array = ['1'] * nbits
    # highest bit: 1 (make sure the number of bits are right)
    # next bit: 0 (make sure we do not enter the scope of other processes even if random numbers are too large)
    # rest bits: random
    # then start increasing and testing prime
    bits_array[1] = '0'
    for _ in range(2, nbits):
        bits_array[_] = '1' if random.random() < 0.5 else '0'
    starting_point = int(''.join(bits_array), base=2)
    starting_point = starting_point + (7 - starting_point % 6)  # 6x + 1
    while True:
        if prime_test(starting_point):
            return starting_point
        starting_point += 6


def generate_pq(nbits: int):
    assert nbits >= 20
    p_bits = int(0.55 * nbits)
    q_bits = nbits - p_bits
    p = generate_prime(p_bits)
    q = generate_prime(q_bits)
    return p, q


def crt(p, q, m1, m2, n):
    """
    x = m1 (mod p)
    x = m2 (mod q)
    then x = m1 q (q^-1 mod p) + m2 p (p^-1 mod q)
    """
    return (m1 * q * pow(q, -1, p) + m2 * p * pow(p, -1, q)) % n


def hash_with_method(m: str, hash_method):
    """
    :param m: string
    :param hash_method:
    :return: int of hex digest
    """
    hash_method = hash_method.lower()
    if hash_method not in ['md5', 'sha256', 'sha224']:
        raise Exception(f"unknown hash method {hash_method}")
    hash_dict = {
        'md5': hashlib.md5,
        'sha256': hashlib.sha256,
        'sha224': hashlib.sha224
    }
    func = hash_dict[hash_method]
    m = m.encode('utf-8')
    m = func(m).hexdigest()
    m = int(m, base=16)
    return m


class PublicKey(object):
    def __init__(self, n, e):
        self.n = n
        self.e = e

    def encrypt(self, m):
        m = m % self.n
        return pow(m, self.e, self.n)

    def verify(self, m, signature, hash_method='md5'):
        """
        :param m: string
        :param signature: int
        """
        digest = hash_with_method(m, hash_method)
        expected_digest = self.encrypt(signature)
        return digest == expected_digest


class PrivateKey(object):
    def __init__(self, p, q, d):
        self.p = p
        self.q = q
        self.n = p * q
        self.phi_n = (p - 1) * (q - 1)
        self.d = d
        self.d1 = self.d % (p - 1)
        self.d2 = self.d % (q - 1)

    def decrypt(self, m):
        m1 = pow(m % self.p, self.d1, self.p)
        m2 = pow(m % self.q, self.d2, self.q)
        m = crt(self.p, self.q, m1, m2, self.n)
        return m

    def sign(self, m, hash_method='md5'):
        """
        :param m: string
        """
        m = hash_with_method(m, hash_method)
        return self.decrypt(m)


def construct_key_pair(p, q, e):
    phi_n = (p - 1) * (q - 1)
    d = pow(e, -1, phi_n)
    private = PrivateKey(p, q, d)
    public = PublicKey(private.n, e)
    return private, public


def generate_key_pair(nbits: int):
    p, q = generate_pq(nbits)
    e = 65537
    return construct_key_pair(p, q, e)


def to_hex(n: int) -> str:
    return hex(n)[2:]


if __name__ == '__main__':
    import argparse, sys
    parser = argparse.ArgumentParser("RSALib")
    parser.add_argument('--nbits', type=int, default=512)
    args = parser.parse_args()
    nbits = args.nbits
    import time, timeit
    now = time.time()
    times = timeit.timeit(lambda : generate_key_pair(nbits), number=10)
    avg_time = times / 10
    print(f'{avg_time} time for {nbits}-bits key generation (averaged over 10 runs)')

    # private, public = construct_key_pair(11, 17, 3)
    # m = 11
    private, public = generate_key_pair(nbits)
    m = random.randint(0, public.n - 1)
    encrypted = public.encrypt(m)
    decrypted = private.decrypt(encrypted)
    assert (m == decrypted)
