import libnum
import gmpy2
import random

import pre_compute


def KGen_NewOpt(k=112, sigma=128, yita=0, secret_key_1=None):
    '''
    :param k:secure parameter
    :param sigma: the bit length of secret_key_1
    :param yita:
    :param bit_len_of_plaintext: plaintext scope
    :param secret_key_1:
    '''
    # step1
    N, P, Q, p, q = Ngen(k)
    # step2
    alpha = gmpy2.mul(p, q)
    beta = gmpy2.mul(gmpy2.sub(P, 1), gmpy2.sub(Q, 1)) // gmpy2.mul(gmpy2.mul(4, p), q)
    # step3
    while True:
        y = gmpy2.mpz(random.randint(0, N))
        if gmpy2.gcd(y, N) == 1:
            break
    h = gmpy2.sub(N, gmpy2.powmod(y, gmpy2.mpz(gmpy2.mul(2, beta)), N))
    # h^N mod N^2
    h_N = gmpy2.powmod(h, N, N ** 2)
    private_key = {
        'alpha': alpha,
        'N': N
    }
    public_key = {
        'N': N,
        'h': h,
        'h_N': h_N,
        'L_k': get_L_k(k),
        'sigma': sigma,
        'table': None,  # pre-computation table
        'L': libnum.randint_bits(sigma + 2)  # the constant in secure multiplication
    }

    if secret_key_1 == None:
        alpha_1 = gmpy2.mpz(libnum.randint_bits(sigma))
    else:
        alpha_1 = secret_key_1
    private_key_1 = {
        'partial_key': alpha_1,
        'N': N}
    private_key_2 = {
        'partial_key': 2 * alpha * gmpy2.invert(2 * alpha, N) - alpha_1 + 2 * yita * N,
        'N': N
    }

    return private_key, public_key, private_key_1, private_key_2


def Enc_NewOpt(public_key, m):
    '''
    the function for encryption
    :param public_key:
    :param m: plaintext
    :return:
    '''
    N = public_key['N']
    h_N = public_key['h_N']
    L_k = public_key['L_k']
    table = public_key['table']

    if m < 0:
        m += N

    # step1
    r = random.randint(0, 2 ** L_k)
    N_square = gmpy2.mpz(N * N)

    if table == None:
        cipher_text = gmpy2.mod(
            gmpy2.mul(
                gmpy2.mod(gmpy2.add(1, gmpy2.mul(m, N)), N_square),
                gmpy2.powmod(h_N, r, N_square))
            , N_square)
    else:
        # with pre-computation table
        mask = gmpy2.mod(pre_compute.compute(r, table, N_square), N_square)
        cipher_text = gmpy2.mod(
            gmpy2.mul(
                gmpy2.mod(gmpy2.add(1, gmpy2.mul(m, N)), N_square),
                mask)
            , N_square)

    return cipher_text


def Dec_NewOpt(private_key, cipher_text):
    '''
    the function for decryption
    :param private_key:
    :param cipher_text:
    :return:
    '''
    alpha = private_key['alpha']
    N = private_key['N']
    parameter = gmpy2.powmod(cipher_text, 2 * alpha, N ** 2)
    inverse = gmpy2.invert(2 * alpha, N)
    m = gmpy2.mod(gmpy2.mul(L_funtion(parameter, N), inverse), N)
    if m > N // 2:
        m = m - N
    return m


def L_funtion(x, N):
    return gmpy2.mod(gmpy2.sub(x, 1) // N, N)


def PDec(partial_private_key, ciphertext):
    '''
    the function for partial decryption
    :param partial_private_key:
    :param ciphertext:
    :return:
    '''
    partial_key = partial_private_key['partial_key']
    N = partial_private_key['N']
    return gmpy2.powmod(ciphertext, partial_key, N ** 2)


def TDec(ciphertext1, ciphertext2, N):
    '''
    threshold decryption
    :param ciphertext1:
    :param ciphertext2:
    :param N:
    :return:
    '''
    paramater = gmpy2.mod(gmpy2.mul(ciphertext1, ciphertext2), N * N)
    m = L_funtion(paramater, N)
    return m




def get_n_k(k=112):
    '''
    get n(k) according to k
    :param k:
    :return:
    '''
    if k == 64:
        return 512
    elif k == 80:
        return 1024
    elif k == 104:
        return 1536
    elif k == 112:
        return 2048
    elif k == 128:
        return 3072
    elif k == 192:
        return 7680
    return 2048


def get_L_k(k=112):
    '''
    get l(k) according to k
    :param k:
    :return:
    '''
    return 4 * k


def is_co_prime(p, q, p_another, q_another):
    '''
    :param p:
    :param q:
    :param p_another:p'
    :param q_another:q'
    :return:
    '''
    if gmpy2.gcd(p_another, q_another) == 1 and gmpy2.mod(p_another, p) != 0 and gmpy2.mod(p_another, q) != 0:
        if gmpy2.mod(q_another, p) != 0 and gmpy2.mod(q_another, q) != 0:
            return True
    return False


def get_odd_len_integer(len):
    '''
    :param len:
    :return:
    '''
    while True:
        a = gmpy2.mpz(libnum.randint_bits(len))
        if gmpy2.is_odd(a):
            return a


def Ngen(k=112):
    '''
    obtain N, P, Q, p, q according to k
    :param k:
    :return: N, P, Q, p, q
    '''
    n_k, l_k = get_n_k(k), get_L_k(k)
    prim = 80

    while True:
        p = gmpy2.mpz(libnum.generate_prime(l_k // 2, prim))
        q = gmpy2.mpz(libnum.generate_prime(l_k // 2, prim))
        while p == q:
            q = gmpy2.mpz(libnum.generate_prime(l_k // 2, prim))

        if gmpy2.is_odd(p) and gmpy2.is_odd(q):
            break

    while True:
        p_another = get_odd_len_integer((n_k - l_k) // 2 - 1)
        q_another = get_odd_len_integer((n_k - l_k) // 2 - 1)
        while p_another == q_another:
            q_another = get_odd_len_integer((n_k - l_k) // 2 - 1)

        if is_co_prime(p, q, p_another, q_another):
            P = gmpy2.add(gmpy2.mul(gmpy2.mul(2, p), p_another), 1)
            Q = gmpy2.add(gmpy2.mul(gmpy2.mul(2, q), q_another), 1)

            P_is_prime, Q_is_prime = gmpy2.is_prime(P), gmpy2.is_prime(Q)

            # case1 P is a prime and Q is not a prime, re-compute Q
            if P_is_prime and not Q_is_prime:
                while True:
                    q_another = get_odd_len_integer((n_k - l_k) // 2 - 1)
                    if gmpy2.gcd(p_another, q_another) == 1 and gmpy2.mod(q_another, p) != 0 and gmpy2.mod(q_another,
                                                                                                           q) != 0:
                        Q = gmpy2.add(gmpy2.mul(gmpy2.mul(2, q), q_another), 1)
                        Q_is_prime = gmpy2.is_prime(Q)
                        if Q_is_prime:
                            break

            # case2 P is a not prime and Q is a prime, re-compute P
            # if P_is_prime and not Q_is_prime:
            if not P_is_prime and Q_is_prime:
                while True:
                    p_another = get_odd_len_integer((n_k - l_k) // 2 - 1)
                    if gmpy2.gcd(p_another, q_another) == 1 and gmpy2.mod(p_another, p) != 0 and gmpy2.mod(p_another,
                                                                                                           q) != 0:
                        P = gmpy2.add(gmpy2.mul(gmpy2.mul(2, p), p_another), 1)
                        P_is_prime = gmpy2.is_prime(P)
                        if P_is_prime:
                            break

            # case3 P and Q are primes
            if P_is_prime and Q_is_prime:
                break
            # case4 P and Q are not primes
    N = P * Q
    return N, P, Q, p, q
