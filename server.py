# -*- coding: utf-8 -*-
"""
Created on Fri Sep 18 09:32:43 2020

@author: Maria Hellstrand
"""

import socket
import DH
import pickle

sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)      # For UDP

udp_host = socket.gethostname()		        # Host IP
udp_port = 12345			                # specified port to connect

#print type(sock) ============> 'type' can be used to see type 
				# of any variable ('sock' here)

sock.bind((udp_host,udp_port))


def key_exchange():
	#generate private key
	privateKey = DH.server_key()

	#recieve shared key from client
	newAddress = sock.recvfrom(1024)
	sharedKey = pickle.loads(newAddress[0])
	
	#calculate server side mix
	serverMix = DH.calc_dh(sharedKey[0], privateKey, sharedKey[1])
	#send server side mix
	sock.sendto(pickle.dumps(serverMix), newAddress[1])
	
	#recieve client mix
	newAddress = sock.recvfrom(1024)
	clientMix = pickle.loads(newAddress[0])
	
	#calculate final DH
	resultDH = DH.calc_dh(clientMix, privateKey, sharedKey[1])
	
	return resultDH

key = key_exchange()
print("server key: ", key)	

#while True:
#	print("Waiting for client...")
#	data,addr = sock.recvfrom(1024)	        #receive data from client
#	print("Received Messages:",data," from",addr)

