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
    #generate private key
    privateKey = DH.client_key()
    
    #generate shared key
    sharedKey = DH.shared_key()
    #send shared key to server
    sock.sendto(pickle.dumps(sharedKey), (udp_host,udp_port))

    #calculate client mix
    clientValue = DH.calc_dh(sharedKey[0], privateKey, sharedKey[1])
    #send client mix
    sock.sendto(pickle.dumps(clientValue), (udp_host,udp_port))
    #recieve server mix
    newAddress = sock.recvfrom(1024)
    serverMix = pickle.loads(newAddress[0])

    #calculate final DH
    resultDH = DH.calc_dh(serverMix, privateKey, sharedKey[1])

    return resultDH
    


key = key_exchange()
print("Client key: ", key)			        

msg = "Hello Python!"
print("UDP target IP:", udp_host)
print("UDP target Port:", udp_port)

sock.sendto(msg.encode('utf-8'),(udp_host,udp_port))		# Sending message to UDP server


