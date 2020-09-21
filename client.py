# -*- coding: utf-8 -*-
"""
Created on Fri Sep 18 09:35:37 2020

@author: Maria Hellstrand
"""

import socket
import DH
import pickle

sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)      # For UDP

udp_host = socket.gethostname()		# Host IP
udp_port = 12345                    # specified port to connect

def key_exchange():
    privateKey = DH.client_key()
    sock.sendto(pickle.dumps(privateKey), (udp_host,udp_port))
    sharedKey = DH.shared_key()
    #send shared key to server
    sock.sendto(pickle.dumps(sharedKey), (udp_host,udp_port))
    #calculate client side dh value
    clientValue = DH.calc_dh(sharedKey[0], privateKey, sharedKey[1])
    sock.sendto(pickle.dumps(clientValue), (udp_host,udp_port))
    serverMix = pickle.loads(sock.recvfrom(1024)[0])
    #calculate final DH
    resultDH = DH.calc_dh(serverMix, privateKey, sharedKey[1])
    #testar nyckalr
    
    sock.sendto(pickle.dumps(resultDH), (udp_host,udp_port))
    

key_exchange()			        

msg = "Hello Python!"
print("UDP target IP:", udp_host)
print("UDP target Port:", udp_port)

sock.sendto(msg.encode('utf-8'),(udp_host,udp_port))		# Sending message to UDP server


