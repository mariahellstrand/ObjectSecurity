import socket
import DH
import pickle
import encryptor


udp_host = socket.gethostname()		        # Host IP
udp_port = 12345			                # specified port to connect
server_dir = "./Nonce_Log/"					#directory to log timestamps
server_logs = "server-logs"					#file to log servers timestamps

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
		print("Waiting for message from client...")
		newAddress = sock.recvfrom(1024)
		encrypted_data = pickle.loads(newAddress[0])
		decrypted_data = encryptor.decrypt(encrypted_data, key)

		message = decrypted_data[0]
		nonce = decrypted_data[1]

		if encryptor.isNonceValid(nonce, server_dir, server_logs):
			print("Recieved message: " + message)
			sendBack = ""			

			if(message == "1"):
				sendBack = "Good Morning!"
			elif (message == "2"):
				sendBack = "You're beautiful"
			elif (message == "3"):
				sendBack = "You can do it!"
			elif(message == "4"):
				sendBack = "Good night!"
			else:
				sendBack = "invalid choice"	

			sock.sendto(pickle.dumps(sendBack), newAddress[1])
		else:
			print("Nonce not valid. The package will be dismissed")
			


if __name__ == '__main__':
    Main()