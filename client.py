# coding=utf-8
import pickle
import socket
import struct

import paillier_NewOpt
import config
import pre_compute


# the function of creating the socket of client
def init_client_socket(ip, port):
    sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_ip_port = (ip, port)
    sk.connect(server_ip_port)
    return sk


def receive_data(link: socket):
    '''
    the function of receiving data
    '''
    length＿data = link.recv(4)
    try:
        length = struct.unpack('i', length＿data)[0]
    except struct.error:
        exit()

    recv_size = 0  # the size of data that has already received
    recv_msg = b''  # the data that has already received

    while recv_size < length:
        # r_msg = link.recv(1024)
        r_msg = link.recv(length - recv_size)
        recv_msg += r_msg
        recv_size += len(r_msg)
    return recv_msg


def my_send(link: socket, data):
    '''
    the function of sending data
    '''
    length = len(data)
    data_length = struct.pack('i', length)
    link.send(data_length)
    link.sendall(data)


def my_dumps(data):
    '''
    dumps data to bytes
    '''
    return pickle.dumps(obj=data, protocol=4)


def sec_mul(e_x, e_y, cp_link: socket):
    '''
    secure multiplication
    '''
    data = ['mul', e_x, e_y]
    my_send(cp_link, my_dumps(data))
    data_recv = receive_data(cp_link)
    time_, e_xy = pickle.loads(data_recv)
    return time_, e_xy


def sec_cmp(e_x, e_y, cp_link: socket):
    '''
    secure comparison
    '''
    data = ['cmp', e_x, e_y]
    my_send(cp_link, my_dumps(data))
    data_recv = receive_data(cp_link)
    time_, e_u = pickle.loads(data_recv)
    return time_, e_u


def sec_ssba(e_x, cp_link: socket):
    '''
    secure sign bit-acquisition
    '''
    data = ['ssba', e_x]
    my_send(cp_link, my_dumps(data))
    data_recv = receive_data(cp_link)
    received_data = pickle.loads(data_recv)
    time_, e_s, another_x = received_data[0], received_data[1], received_data[2]
    return time_, e_s, another_x


def sec_div(e_x, e_y, cp_link: socket):
    '''
    secure divison
    '''
    data = ['div', e_x, e_y]
    my_send(cp_link, my_dumps(data))
    data_recv = receive_data(cp_link)
    received_data = pickle.loads(data_recv)
    time_, e_q, e_e = received_data[0], received_data[1], received_data[2]
    return time_, e_q, e_e


if __name__ == "__main__":
    # create the secret key
    private_key, public_key, private_key_1, private_key_2 = paillier_NewOpt.KGen_NewOpt()

    # create the link to csp server
    csp_link = init_client_socket(ip=config.csp_ip, port=config.csp_port_for_client)
    # create the link to cp server
    cp_link = init_client_socket(ip=config.cp_ip, port=config.cp_port)

    # create the pre-computation table for speeding up encryption
    table = pre_compute.construct_table(public_key['h_N'], public_key['N'] ** 2)
    public_key['table'] = table

    username = 'user'

    # send the username, public key and partially private key 2 to csp server
    data_list = [username, public_key, private_key_2]
    my_send(csp_link, my_dumps(data_list))
    # receive the confirmation from csp
    data_recv = receive_data(csp_link)
    print(data_recv.decode("utf-8"))

    # send the username, public key and partially private key 1 to cp server
    data_list = [username, public_key, private_key_1]
    my_send(cp_link, my_dumps(data_list))
    # receive the confirmation from cp
    data_recv = receive_data(cp_link)
    print(data_recv.decode("utf-8"))

    '''



        correction test



    '''
    plaintext1 = [-i for i in range(1, 21, 1)]
    plaintext1.append(99)
    plaintext1.append(100)
    plaintext1.append(101)
    plaintext2 = [i for i in range(20, 0, -1)]
    plaintext2.append(101)
    plaintext2.append(100)
    plaintext2.append(99)
    print(f"plaintext list 1:{plaintext1}")
    print(f"plaintext list 2:{plaintext2}")

    ciphertext_list1 = []
    ciphertext_list2 = []
    result_smul = []
    result_scmp = []
    result_ssba = []
    result_div = []
    for i in range(len(plaintext1)):
        ciphertext_list1.append(paillier_NewOpt.Enc_NewOpt(public_key, plaintext1[i]))
        ciphertext_list2.append(paillier_NewOpt.Enc_NewOpt(public_key, plaintext2[i]))
        result_smul.append(plaintext1[i] * plaintext2[i])
        result_scmp.append(0 if plaintext1[i] >= plaintext2[i] else 1)
        result_ssba.append([0 if plaintext1[i] >= 0 else 1, abs(plaintext1[i])])

    print("\nmultiplication test")
    print("result under plaintext:")
    print(result_smul)
    result_dec_smul = []
    for i in range(len(plaintext1)):
        time_, e_xy = sec_mul(ciphertext_list1[i], ciphertext_list2[i], cp_link)
        result_dec_smul.append(paillier_NewOpt.Dec_NewOpt(private_key, e_xy))
    print("smul -- result under ciphertext:")
    print(result_dec_smul)
    flag = True
    for i in range(len(plaintext1)):
        result_dec_smul[i] = int(result_dec_smul[i])
        if result_dec_smul[i] != result_smul[i]:
            print("wrong\n")
            flag = False
            break
    if flag:
        print("all correct\n")

    print("\ncomparison test")
    print("result under plaintext:")
    print(result_scmp)
    result_dec_scmp = []
    for i in range(len(plaintext1)):
        time_, e_u = sec_cmp(ciphertext_list1[i], ciphertext_list2[i], cp_link)
        result_dec_scmp.append(paillier_NewOpt.Dec_NewOpt(private_key, e_u))
    print("scmp -- result under ciphertext:")
    print(result_dec_scmp)
    flag = True
    for i in range(len(plaintext1)):
        result_dec_scmp[i] = int(result_dec_scmp[i])
        if result_dec_scmp[i] != result_scmp[i]:
            print("wrong")
            flag = False
            break
    if flag:
        print("all correct\n")

    print("\ntest of secure sign bit-acquisition")
    print("result under plaintext:")
    print(result_ssba)
    result_dec_ssba = []
    for i in range(len(plaintext1)):
        time_, e_s, another_x = sec_ssba(ciphertext_list1[i], cp_link)
        result_dec_ssba.append(
            [paillier_NewOpt.Dec_NewOpt(private_key, e_s), paillier_NewOpt.Dec_NewOpt(private_key, another_x)])
    print("ssba -- result under ciphertext:")
    print(result_dec_ssba)
    flag = True
    for i in range(len(plaintext1)):
        result_dec_ssba[i][0] = int(result_dec_ssba[i][0])
        result_dec_ssba[i][1] = int(result_dec_ssba[i][1])
        if result_dec_ssba[i][1] != result_ssba[i][1] or result_dec_ssba[i][0] != result_ssba[i][0]:
            print("wrong")
            flag = False
            break
    if flag:
        print("all correct\n")

    print("\nsecure division test")
    plaintext_div_1 = [i for i in range(20)]
    plaintext_div_1.append(99)
    plaintext_div_1.append(100)
    plaintext_div_1.append(101)
    plaintext_div_2 = [i for i in range(20, 0, -1)]
    plaintext_div_2.append(101)
    plaintext_div_2.append(100)
    plaintext_div_2.append(99)
    print(f"plaintext_list_for_div_1:{plaintext_div_1}")
    print(f"plaintext_list_for_div_2:{plaintext_div_2}")
    ciphertext_list1_div = []
    ciphertext_list2_div = []
    for i in range(len(plaintext_div_1)):
        ciphertext_list1_div.append(paillier_NewOpt.Enc_NewOpt(public_key, plaintext_div_1[i]))
        ciphertext_list2_div.append(paillier_NewOpt.Enc_NewOpt(public_key, plaintext_div_2[i]))
        result_div.append([plaintext_div_1[i] // plaintext_div_2[i], plaintext_div_1[i] % plaintext_div_2[i]])
    print("result under plaintext:")
    print(result_div)
    result_dec_sdiv = []
    for i in range(len(plaintext1)):
        time_, e_q, e_e = sec_div(ciphertext_list1_div[i], ciphertext_list2_div[i], cp_link)
        result_dec_sdiv.append(
            [paillier_NewOpt.Dec_NewOpt(private_key, e_q), paillier_NewOpt.Dec_NewOpt(private_key, e_e)])
    print("sdiv -- result under ciphertext:")
    print(result_dec_sdiv)
    flag = True
    for i in range(len(plaintext1)):
        result_dec_sdiv[i][0] = int(result_dec_sdiv[i][0])
        result_dec_sdiv[i][1] = int(result_dec_sdiv[i][1])
        if result_dec_sdiv[i][0] != result_div[i][0] or result_dec_sdiv[i][1] != result_div[i][1]:
            print("wrong")
            flag = False
            break
    if flag:
        print("all correct\n")
