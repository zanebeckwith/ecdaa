#!/usr/bin/env python3

import base64
import json
import sys

def extract_sk(authsk_filename):
    sk_filename = 'sk.bin'

    with open(authsk_filename, 'r') as authsk_file:
        sk = base64.urlsafe_b64decode(authsk_file.read())

    with open(sk_filename, 'wb') as sk_file:
        sk_file.write(sk)

def extract_cred(join_msg2_filename):
    cred_filename = 'cred.bin'

    with open(join_msg2_filename, 'r') as join_msg2_file:
        join_msg2 = json.load(join_msg2_file)
        a = base64.urlsafe_b64decode(join_msg2['JoinMessage2']['a'])
        b = base64.urlsafe_b64decode(join_msg2['JoinMessage2']['b'])
        c = base64.urlsafe_b64decode(join_msg2['JoinMessage2']['c'])
        d = base64.urlsafe_b64decode(join_msg2['JoinMessage2']['d'])

    with open(cred_filename, 'wb') as cred_file:
        cred_file.write(a)
        cred_file.write(b)
        cred_file.write(c)
        cred_file.write(d)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('usage: ' + sys.argv[0] + ' <authsk-file> <join-msg-2-file>')
        exit(1)
    extract_sk(sys.argv[1])
    extract_cred(sys.argv[2])
