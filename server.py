import socket
import DH
import pickle
import encryptor


udp_host = socket.gethostname()		        # Host IP
udp_port = 12345			                # specified port to connect


def key_exchange(sock):
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


def Main():
	#set up socket
	sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)      # For UDP
	sock.bind((udp_host,udp_port))
	print("socket opened. Waiting for client")

	#key exhcange
	key = key_exchange(sock)
	print("Agreed shared key: ", key)

	while True:
		print("Waiting for message from client")
		newAddress = sock.recvfrom(1024)
		encrypted_data = pickle.loads(newAddress[0])
		decrypted_data = encryptor.decrypt(encrypted_data, key)

		print(decrypted_data)



if __name__ == '__main__':
    Main()