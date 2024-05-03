import time

import gmpy2
import libnum

block_size = 5  # the bit length of each block


def construct_table(g, N_square, l=448):
    '''
    construct a pre-computation table
    :param g: base
    :param N_square: the square of modulus N
    :param l: the bit length of exponent
    :return:
    '''
    b = block_size
    l_div_b_ceil = libnum.ceil(l, b)
    base = g
    table = []
    for i in range(l_div_b_ceil):
        row = []
        for j in range(2 ** b):
            element = gmpy2.powmod(
                gmpy2.powmod(base, gmpy2.powmod(2, gmpy2.mod(gmpy2.mul(i, b), N_square), N_square), N_square), j,
                N_square)
            row.append(element)
        table.append(row)
    return table


def convert_into_block(num):
    '''
    convert a number into blocks
    :param num:
    :return:
    '''
    b = block_size
    l = gmpy2.bit_length(num)
    cnt = libnum.ceil(l, b)
    num_in_bit = bin(num)[2:]
    fill_0 = '0' * (0 if l % b == 0 else b - l % b)
    num_in_bit = fill_0 + num_in_bit

    block_list = []
    left, right = len(num_in_bit) - b, len(num_in_bit)
    for i in range(cnt):
        block_list.append(int(num_in_bit[left:right], 2))
        left -= b
        right -= b
    return block_list


def compute(x, table, N_square):
    '''
    :param x: exponent
    :param table: pre-computation table
    :param N_square: the square of modulus N
    :return:
    '''
    blocks = convert_into_block(gmpy2.mpz(x))
    ans = 1
    for i in range(len(blocks)):
        ans = gmpy2.mod(gmpy2.mul(ans, table[i][blocks[i]]), N_square)
    return ans
