# -*- coding: utf-8 -*-
"""
Created on Fri Sep 18 09:32:43 2020

@author: Maria Hellstrand
"""

import socket

sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)      # For UDP

udp_host = socket.gethostname()		        # Host IP
udp_port = 12345			                # specified port to connect

#print type(sock) ============> 'type' can be used to see type 
				# of any variable ('sock' here)

sock.bind((udp_host,udp_port))

while True:
	print("Waiting for client...")
	data,addr = sock.recvfrom(1024)	        #receive data from client
	print("Received Messages:",data," from",addr)
