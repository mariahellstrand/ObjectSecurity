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
	clientPrivat = pickle.loads(sock.recvfrom(1024)[0])
	privateKey = DH.server_key()
	sharedKey = pickle.loads(sock.recvfrom(1024)[0])
	#print(sharedKey)
	#calculate server side dh value
	serverValue = DH.calc_dh(sharedKey[0], privateKey, sharedKey[1])
	sock.sendto(pickle.dumps(serverValue), (udp_host, udp_port))
	#print(serverValue)
	clientMix = pickle.loads(sock.recvfrom(1024)[0])
	#print(clientMix)
	#calculate final DH
	resultDH = DH.calc_dh(clientMix, privateKey, sharedKey[1])
	#test
	
	clientResult = pickle.loads(sock.recvfrom(1024)[0])
	print("server privat: ",privateKey)
	print("client privat: " ,clientPrivat)
	print("server blandning ", serverValue)
	print("client blandning ", clientMix)
	print("server DH: ", resultDH)
	print("client DH: ", clientResult)

key_exchange()	

while True:
	print("Waiting for client...")
	data,addr = sock.recvfrom(1024)	        #receive data from client
	print("Received Messages:",data," from",addr)

