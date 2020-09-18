# -*- coding: utf-8 -*-
"""
Created on Fri Sep 18 10:47:37 2020

@author: Maria Hellstrand
"""

import random

#server private key
def server_key():
    return random.randint(1,999);

#client private key
def client_key():
    return random.randint(1,999);

def shared_key():
    base = random.randint(1,99999)
    modulo = random.randint(1,99999)
    return base, modulo;

def calc_dh(a, b, c):
    if (b == 1 ):
        return a;
    else:
        return ((pow (a,b)) % c)
