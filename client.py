# -*- coding: utf-8 -*-
"""
Created on Fri Sep 18 09:35:37 2020

@author: Maria Hellstrand
"""

import socket

sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)      # For UDP

udp_host = socket.gethostname()		# Host IP
udp_port = 12345			        # specified port to connect

msg = "Hello Python!"
print("UDP target IP:", udp_host)
print("UDP target Port:", udp_port)

sock.sendto(msg.encode('utf-8'),(udp_host,udp_port))		# Sending message to UDP server