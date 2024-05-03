# coding=utf-8
import pickle
import random
import socket
import struct
import threading
import time

import gmpy2
import libnum

import paillier_NewOpt
import config


# create the socker in server side
def init_socket_server(ip, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ip_port = (ip, port)
    server_socket.bind(ip_port)
    server_socket.listen(100)
    return server_socket


def init_client_socket(ip, port):
    sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_ip_port = (ip, port)
    sk.connect(server_ip_port)
    return sk


def receive_data(link: socket):
    length＿data = link.recv(4)
    try:
        length = struct.unpack('i', length＿data)[0]
    except struct.error:
        exit()

    recv_size = 0
    recv_msg = b''

    while recv_size < length:
        # r_msg = link.recv(1024)
        r_msg = link.recv(length - recv_size)
        recv_msg += r_msg
        recv_size += len(r_msg)
    return recv_msg


def my_send(link: socket, data):
    length = len(data)
    data_length = struct.pack('i', length)
    link.send(data_length)
    link.sendall(data)


def my_dumps(data):
    return pickle.dumps(obj=data, protocol=4)


def sec_mul(username, e_x, e_y, tuple_cp: dict, public_key, partial_key, csp_link: socket):
    '''
    secure multiplication, cp part
    :param username:
    '''
    N = public_key['N']
    N_square = N ** 2

    L = public_key['L']

    # step 1,cp
    r1, r2, e_r1, e_r2, e_negative_r1_r2 = tuple_cp['r_1'], tuple_cp['r_2'], tuple_cp['e_r_1'], tuple_cp['e_r_2'], \
        tuple_cp[
            'e_negative_r1_r2']

    X = gmpy2.mod(gmpy2.mul(e_x, e_r1), N_square)
    Y = gmpy2.mod(gmpy2.mul(e_y, e_r2), N_square)
    C = gmpy2.mod(gmpy2.mul(gmpy2.powmod(X, L, N_square), Y), N_square)
    C1 = paillier_NewOpt.PDec(partial_private_key=partial_key, ciphertext=C)

    # send C,C1 to CSP
    data_list = [username, 'mul', C, C1]
    my_send(csp_link, my_dumps(data_list))

    # receive encrypted (x+r1)*(y+r2) from csp
    data_recv = receive_data(csp_link)
    e_x_add_r1_mul_y_add_r2 = pickle.loads(data_recv)[0]

    # step3,cp
    e_negative_r2x = gmpy2.powmod(e_x, -r2, N_square)
    e_negative_r1y = gmpy2.powmod(e_y, -r1, N_square)

    e_xy = gmpy2.mod(gmpy2.mul(
        gmpy2.mod(gmpy2.mul(gmpy2.mod(gmpy2.mul(e_x_add_r1_mul_y_add_r2, e_negative_r2x), N_square), e_negative_r1y),
                  N_square), e_negative_r1_r2), N_square)
    return e_xy


def sec_cmp(username, e_x, e_y, tuple_cp: dict, public_key, partial_key, csp_link: socket):
    '''
    secure comparison, cp part
    '''
    N = public_key['N']
    N_square = N ** 2

    pi = random.randint(0, 1)

    # step 1,cp
    r_1, r_2, e_r1_add_r2, e_r2 = tuple_cp['r_3'], tuple_cp['r_4'], tuple_cp['e_r3_add_r4'], tuple_cp['e_r_4']

    if pi == 0:
        D = gmpy2.mod(
            gmpy2.mul(
                gmpy2.powmod(gmpy2.mod(gmpy2.mul(e_x, gmpy2.powmod(e_y, gmpy2.sub(N, 1), N_square)), N_square), r_1,
                             N_square),
                e_r1_add_r2), N_square)
    else:
        D = gmpy2.mod(
            gmpy2.mul(gmpy2.powmod(gmpy2.mod(gmpy2.mul(e_y, gmpy2.powmod(e_x, -1, N_square)), N_square), r_1, N_square),
                      e_r2),
            N_square)
    D1 = paillier_NewOpt.PDec(partial_key, D)

    # send D,D1 to csp
    data_list = [username, 'cmp', D, D1]
    my_send(csp_link, my_dumps(data_list))

    # receive data from csp
    data_recv = receive_data(csp_link)
    e_u0 = pickle.loads(data_recv)[0]

    # # step3,cp
    if pi == 0:
        e_u = e_u0
    else:
        e_1_for_cp = tuple_cp['e_1']
        e_u = gmpy2.mod(gmpy2.mul(e_1_for_cp, gmpy2.powmod(e_u0, -1, N_square)), N_square)
    return e_u


def sec_ssba(username, e_x, tuple_cp: dict, public_key, partial_key, csp_link: socket):
    '''
    secure sign bit-acquisition
    '''
    N = public_key['N']
    N_square = N ** 2

    # step1,cp
    e_0, e_1 = tuple_cp["e_0"], tuple_cp["e_1"]

    tuple_scmp = {}
    tuple_scmp['r_3'] = tuple_cp['r_3']
    tuple_scmp['r_4'] = tuple_cp['r_4']
    tuple_scmp['e_r3_add_r4'] = tuple_cp['e_r3_add_r4']
    tuple_scmp['e_r_4'] = tuple_cp['e_r_4']
    tuple_scmp['e_1'] = tuple_cp['e_1']

    # step2,csp,cp
    e_s = sec_cmp(username, e_x, e_0, tuple_scmp, public_key, partial_key, csp_link)

    # step3,cp
    e_1sub_2s = gmpy2.mod(gmpy2.mul(e_1, gmpy2.powmod(e_s, -2, N_square)), N_square)

    tuple_smul = {}
    tuple_smul['r_1'] = tuple_cp['r_1']
    tuple_smul['r_2'] = tuple_cp['r_2']
    tuple_smul['e_r_1'] = tuple_cp['e_r_1']
    tuple_smul['e_r_2'] = tuple_cp['e_r_2']
    tuple_smul['e_negative_r1_r2'] = tuple_cp['e_negative_r1_r2']
    # step4,cp,csp
    x_another = gmpy2.mod(sec_mul(username, e_1sub_2s, e_x, tuple_smul, public_key, partial_key, csp_link), N_square)

    return e_s, x_another


def sec_div(username, e_x, e_y, tuple_cp: dict, public_key, partial_key, csp_link: socket, l=10):
    '''
    secure division
    '''
    N = public_key['N']
    N_square = N ** 2

    # step_1,cp
    e_0, e_1 = tuple_cp["e_0"], tuple_cp["e_1"]

    e_q = e_0

    while l >= 0:
        temp_sdiv_list = tuple_cp['random_number_list'][l]

        # step_2,cp
        e_c = gmpy2.powmod(e_y, 2 ** l, N_square)

        tuple_scmp = {}
        tuple_scmp['r_3'] = temp_sdiv_list['r_3']
        tuple_scmp['r_4'] = temp_sdiv_list['r_4']
        tuple_scmp['e_r3_add_r4'] = temp_sdiv_list['e_r3_add_r4']
        tuple_scmp['e_r_4'] = temp_sdiv_list['e_r_4']
        tuple_scmp['e_1'] = e_1
        # step_3,cp,csp
        e_u = gmpy2.mod(sec_cmp(username, e_x, e_c, tuple_scmp, public_key, partial_key, csp_link), N_square)

        # step_4,cp
        e_u_another = gmpy2.mod(gmpy2.mul(e_1, gmpy2.powmod(e_u, -1, N_square)), N_square)
        e_q = gmpy2.mod(gmpy2.mul(e_q, gmpy2.powmod(e_u_another, 2 ** l, N_square)), N_square)

        tuple_smul = {}
        tuple_smul['r_1'] = temp_sdiv_list['r_1']
        tuple_smul['r_2'] = temp_sdiv_list['r_2']
        tuple_smul['e_r_1'] = temp_sdiv_list['e_r_1']
        tuple_smul['e_r_2'] = temp_sdiv_list['e_r_2']
        tuple_smul['e_negative_r1_r2'] = temp_sdiv_list['e_negative_r1_r2']
        # step_5, cp,csp
        e_m = gmpy2.mod(sec_mul(username, e_u_another, e_c, tuple_smul, public_key, partial_key, csp_link), N_square)

        # step_6, cp
        e_x = gmpy2.mod(gmpy2.mul(e_x, gmpy2.powmod(e_m, -1, N_square)), N_square)

        l -= 1

    # step_7
    e_e = e_x
    return e_q, e_e


def execute_soci_plus_protocol(client_socket: socket, keys: dict):
    # receive public key and partial private key from client
    data_recv = receive_data(client_socket)
    data_list = pickle.loads(data_recv)
    username, public_key, partial_key = data_list[0], data_list[1], data_list[2]
    print(f"cp server has received keys of {username}")
    my_send(client_socket, f"cp server has received keys of {username}".encode("utf-8"))

    keys[username] = [public_key, partial_key]

    # construct tuple
    tuple_smul = {}
    tuple_smul['r_1'] = libnum.randint_bits(128)
    tuple_smul['r_2'] = libnum.randint_bits(128)
    tuple_smul['e_r_1'] = paillier_NewOpt.Enc_NewOpt(public_key, tuple_smul['r_1'])
    tuple_smul['e_r_2'] = paillier_NewOpt.Enc_NewOpt(public_key, tuple_smul['r_2'])
    tuple_smul['e_negative_r1_r2'] = paillier_NewOpt.Enc_NewOpt(public_key, -tuple_smul['r_1'] * tuple_smul['r_2'])

    tuple_scmp = {}
    r_3 = random.randint(1, 2 ** 128)
    N = public_key['N']
    mid = N // 2
    while True:
        r = random.randint(1, 2 ** 128)
        if r < r_3:
            break
    r_4 = mid - r
    tuple_scmp['r_3'] = r_3
    tuple_scmp['r_4'] = r_4
    tuple_scmp['e_r3_add_r4'] = paillier_NewOpt.Enc_NewOpt(public_key, tuple_scmp['r_3'] + tuple_scmp['r_4'])
    tuple_scmp['e_r_4'] = paillier_NewOpt.Enc_NewOpt(public_key, tuple_scmp['r_4'])
    tuple_scmp['e_1'] = paillier_NewOpt.Enc_NewOpt(public_key, 1)

    tuple_ssba = {}
    tuple_ssba['r_1'] = libnum.randint_bits(128)
    tuple_ssba['r_2'] = libnum.randint_bits(128)
    tuple_ssba['e_r_1'] = paillier_NewOpt.Enc_NewOpt(public_key, tuple_ssba['r_1'])
    tuple_ssba['e_r_2'] = paillier_NewOpt.Enc_NewOpt(public_key, tuple_ssba['r_2'])
    tuple_ssba['e_negative_r1_r2'] = paillier_NewOpt.Enc_NewOpt(public_key, -tuple_ssba['r_1'] * tuple_ssba['r_2'])
    r_3 = random.randint(1, 2 ** 128)
    N = public_key['N']
    mid = N // 2
    while True:
        r = random.randint(1, 2 ** 128)
        if r < r_3:
            break
    r_4 = mid - r
    tuple_ssba['r_3'] = r_3
    tuple_ssba['r_4'] = r_4
    tuple_ssba['e_r3_add_r4'] = paillier_NewOpt.Enc_NewOpt(public_key, tuple_ssba['r_3'] + tuple_ssba['r_4'])
    tuple_ssba['e_r_4'] = paillier_NewOpt.Enc_NewOpt(public_key, tuple_ssba['r_4'])
    tuple_ssba['e_1'] = paillier_NewOpt.Enc_NewOpt(public_key, 1)
    tuple_ssba['e_0'] = paillier_NewOpt.Enc_NewOpt(public_key, 0)

    tuple_sdiv = {}
    tuple_sdiv['e_1'] = paillier_NewOpt.Enc_NewOpt(public_key, 1)
    tuple_sdiv['e_0'] = paillier_NewOpt.Enc_NewOpt(public_key, 0)
    l = 10
    random_number_list = []
    for i in range(l + 1):
        temp_sdiv_dict = {}
        temp_sdiv_dict['r_1'] = libnum.randint_bits(128)
        temp_sdiv_dict['r_2'] = libnum.randint_bits(128)
        temp_sdiv_dict['e_r_1'] = paillier_NewOpt.Enc_NewOpt(public_key, temp_sdiv_dict['r_1'])
        temp_sdiv_dict['e_r_2'] = paillier_NewOpt.Enc_NewOpt(public_key, temp_sdiv_dict['r_2'])
        temp_sdiv_dict['e_negative_r1_r2'] = paillier_NewOpt.Enc_NewOpt(public_key,
                                                                        -temp_sdiv_dict['r_1'] * temp_sdiv_dict['r_2'])
        r_3 = random.randint(1, 2 ** 128)
        N = public_key['N']
        mid = N // 2
        while True:
            r = random.randint(1, 2 ** 128)
            if r < r_3:
                break
        r_4 = mid - r
        temp_sdiv_dict['r_3'] = r_3
        temp_sdiv_dict['r_4'] = r_4
        temp_sdiv_dict['e_r3_add_r4'] = paillier_NewOpt.Enc_NewOpt(public_key,
                                                                   temp_sdiv_dict['r_3'] + temp_sdiv_dict['r_4'])
        temp_sdiv_dict['e_r_4'] = paillier_NewOpt.Enc_NewOpt(public_key, temp_sdiv_dict['r_4'])
        random_number_list.append(temp_sdiv_dict)
    tuple_sdiv['random_number_list'] = random_number_list

    # create socker, using for interact with csp
    csp_link = init_client_socket(ip=config.csp_ip, port=config.csp_port_for_cp)

    while True:
        try:
            try:
                data_recv = receive_data(client_socket)
                data_list = pickle.loads(data_recv)
            except EOFError:
                pass
            if data_list[0] == 'mul':
                e_x, e_y = data_list[1], data_list[2]
                time_start_mul = time.time()  # record the time of starting the protocol
                e_x_y = sec_mul(username, e_x, e_y, tuple_smul, public_key, partial_key, csp_link)
                time_end_mul = time.time()  # record the time of finishing the protocol
                my_send(client_socket, my_dumps([time_end_mul - time_start_mul, e_x_y]))
            if data_list[0] == 'cmp':
                e_x, e_y = data_list[1], data_list[2]
                time_start_cmp = time.time()
                u = sec_cmp(username, e_x, e_y, tuple_scmp, public_key, partial_key, csp_link)
                time_end_cmp = time.time()
                my_send(client_socket, my_dumps([time_end_cmp - time_start_cmp, u]))
            if data_list[0] == 'ssba':
                e_x = data_list[1]
                time_start_ssba = time.time()
                e_s, x_another = sec_ssba(username, e_x, tuple_ssba, public_key, partial_key, csp_link)
                time_end_ssba = time.time()
                my_send(client_socket, my_dumps([time_end_ssba - time_start_ssba, e_s, x_another]))
            if data_list[0] == 'div':
                e_x, e_y = data_list[1], data_list[2]
                time_start_div = time.time()
                e_q, e_e = sec_div(username, e_x, e_y, tuple_sdiv, public_key, partial_key, csp_link)
                time_end_div = time.time()
                my_send(client_socket, my_dumps([time_end_div - time_start_div, e_q, e_e]))
        except (ConnectionAbortedError, ConnectionResetError):
            client_socket.close()
            csp_link.close()
            exit()


if __name__ == "__main__":
    # store the keys of each client
    keys = {}

    # create socket
    cp_server_socket = init_socket_server(ip=config.cp_ip, port=config.cp_port)

    while True:
        client_socket, addr = cp_server_socket.accept()
        print(f"connection established：{client_socket}")
        threading.Thread(target=execute_soci_plus_protocol, args=(client_socket, keys)).start()
