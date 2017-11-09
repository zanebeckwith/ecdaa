#!/usr/bin/env python3

import json
import base64
import sys

authsk_filename = 'authsk'
join_msg2_filename = 'msg2'
ipk_fido_filename = 'ipk'

def encode_sk(sk_filename):
    with open(sk_filename, 'rb') as sk_file:
        with open(authsk_filename, 'w') as authsk_file:
            authsk_file.write(base64.urlsafe_b64encode(sk_file.read()).decode())

def convert_cred_to_join_msg(cred_filename, cred_sig_filename):
    with open(cred_filename, 'rb') as cred_file:
        cred_file_as_bytes = cred_file.read()
        a = base64.urlsafe_b64encode(cred_file_as_bytes[:65]).decode()
        b = base64.urlsafe_b64encode(cred_file_as_bytes[65:130]).decode()
        c = base64.urlsafe_b64encode(cred_file_as_bytes[130:195]).decode()
        d = base64.urlsafe_b64encode(cred_file_as_bytes[195:]).decode()
    with open(cred_sig_filename, 'rb') as cred_sig_file:
        cred_sig_file_as_bytes = cred_sig_file.read()
        c2 = base64.urlsafe_b64encode(cred_sig_file_as_bytes[:32]).decode()
        s2 = base64.urlsafe_b64encode(cred_sig_file_as_bytes[32:]).decode()

    join_msg2 = {'JoinMessage2': {
        'a': a,
        'b': b,
        'c': c,
        'd': d,
        'c2': c2,
        's2': s2}}

    with open(join_msg2_filename, 'w') as join_msg2_file:
        json.dump(join_msg2, join_msg2_file)

def convert_ipk_to_fido(ipk_in_filename):
    with open(ipk_in_filename, 'rb') as ipk_in_file:
        ipk_in_file_as_bytes = ipk_in_file.read()
        X = base64.urlsafe_b64encode(ipk_in_file_as_bytes[:129]).decode()
        Y = base64.urlsafe_b64encode(ipk_in_file_as_bytes[129:258]).decode()
        c = base64.urlsafe_b64encode(ipk_in_file_as_bytes[258:290]).decode()
        sx = base64.urlsafe_b64encode(ipk_in_file_as_bytes[290:322]).decode()
        sy = base64.urlsafe_b64encode(ipk_in_file_as_bytes[322:]).decode()

    ipk_fido = {'EcDaaTrustAnchor': {
        'X': X,
        'Y': Y,
        'c': c,
        'sx': sx,
        'sy': sy}}

    with open(ipk_fido_filename, 'w') as ipk_fido_file:
        json.dump(ipk_fido, ipk_fido_file)

if __name__ == '__main__':
    if len(sys.argv) != 5:
        print('usage: ' + sys.argv[0] + ' <sk-file> <cred-file> <cred-sig-file> <ipk-file>')
        exit(1)
    encode_sk(sys.argv[1])
    convert_cred_to_join_msg(sys.argv[2], sys.argv[3])
    convert_ipk_to_fido(sys.argv[4])
