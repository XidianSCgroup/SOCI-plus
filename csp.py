# coding=utf-8
import pickle
import socket
import struct
import threading

import gmpy2

import paillier_NewOpt
import config


def init_socket_server(ip, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ip_port = (ip, port)
    server_socket.bind(ip_port)
    server_socket.listen(100)
    return server_socket


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


def sec_mul(data_list, public_key, partial_key, cp_socket: socket):
    '''
    secure multiplication,csp part
    '''
    N = public_key['N']
    L = public_key['L']

    C, C1 = data_list[2], data_list[3]

    # step2，csp
    C2 = paillier_NewOpt.PDec(partial_private_key=partial_key, ciphertext=C)
    Lmulxaddr1_yaddr2 = paillier_NewOpt.TDec(C1, C2, N)
    xaddr1 = Lmulxaddr1_yaddr2 // L
    yaddr2 = Lmulxaddr1_yaddr2 % L
    e_xaddr1_mul_yaddr2 = paillier_NewOpt.Enc_NewOpt(public_key, gmpy2.mod(gmpy2.mul(xaddr1, yaddr2), N))

    # send e_xaddr1_mul_yaddr2 to CP
    data_list = [e_xaddr1_mul_yaddr2]
    my_send(cp_socket, my_dumps(data_list))


def sec_cmp(data_list, tuple_csp: dict, public_key, partial_key, cp_socket: socket):
    '''
    secure comparison, csp part
    '''
    N = public_key['N']
    N_square = N ** 2

    D, D1 = data_list[2], data_list[3]

    # step2,csp
    D2 = paillier_NewOpt.PDec(partial_key, D)
    d = paillier_NewOpt.TDec(D1, D2, N)

    e_0, e_1 = tuple_csp['e_0'], tuple_csp['e_1']
    if d > N // 2:
        e_u0 = e_0
    else:
        e_u0 = e_1

    # send e_u0 to cp
    data_list = [e_u0]
    my_send(cp_socket, my_dumps(data_list))


def receive_keys(csp_socket_to_client: socket, keys: dict, tuple_dict: dict):
    '''
    receive public key and partial private key from client
    :param csp_socket_to_client:
    :param keys:
    :return:
    '''
    while True:
        client_socket, client_addr = csp_socket_to_client.accept()
        data_recv = receive_data(client_socket)
        data_list = pickle.loads(data_recv)
        username, public_key, partial_key = data_list[0], data_list[1], data_list[2]

        # construct tuple
        tuple_csp = {}
        tuple_csp['e_0'] = paillier_NewOpt.Enc_NewOpt(public_key, 0)
        tuple_csp['e_1'] = paillier_NewOpt.Enc_NewOpt(public_key, 1)
        tuple_dict[username] = tuple_csp

        print(f"csp server has received keys of {username}")
        my_send(client_socket, f"csp server has received keys of {username}".encode("utf-8"))
        keys[username] = [public_key, partial_key]
        client_socket.close()


def execute_soci_plus_protocol(cp_socket: socket, keys: dict, tuple_dict: dict):
    try:
        while True:
            try:
                data_recv = receive_data(cp_socket)
                data_list = pickle.loads(data_recv)
            except EOFError:
                pass
            username_ = data_list[0]
            public_key, partial_key = keys[username_][0], keys[username_][1]
            tuple_csp = tuple_dict[username_]
            if data_list[1] == 'mul':
                sec_mul(data_list, public_key, partial_key, cp_socket)
            if data_list[1] == 'cmp':
                sec_cmp(data_list, tuple_csp, public_key, partial_key, cp_socket)
    except (ConnectionAbortedError, ConnectionResetError):
        cp_socket.close()
        exit()


if __name__ == '__main__':
    # store keys of each client
    keys = {}
    # store tuples of each client
    tuple_dict = {}

    # create socket, using for interact with client
    csp_socket_to_client = init_socket_server(ip=config.csp_ip, port=config.csp_port_for_client)
    # create socket, using for interact with cp
    csp_socket_to_cp = init_socket_server(ip=config.csp_ip, port=config.csp_port_for_cp)

    threading.Thread(target=receive_keys, args=(csp_socket_to_client, keys, tuple_dict)).start()

    while True:
        cp_socket, cp_addr = csp_socket_to_cp.accept()
        threading.Thread(target=execute_soci_plus_protocol, args=(cp_socket, keys, tuple_dict)).start()
