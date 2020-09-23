import socket
import DH
import pickle
import encryptor


udp_host = socket.gethostname()		# Host IP
udp_port = 12345                    # specified port to connect
client_dir = "./Nonce_Log/"         #directory to log timestamps
client_logs = "client-logs"         #directory to log clients timestamps

def startConnection(sock):
    print("starting a connection")
    # Starting Diffie Hellman handshake
    key = key_exchange(sock)
    print("Agreed shared key: ", key)
    print("Handshake done")
    return key

def key_exchange(sock):
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
    

def menu():
    commands = ["s","q"]
    print("Type \'type\' to initiate handshake".replace('type', commands[0]))
    print("Type \'type\ to quit".replace('type', commands[1]))


def Main():
    #set up connection and key exchange
    sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)      # For UDP
    key = startConnection(sock)

    while True:
        print("What message would you like to send?: ")
        message = input(": ")
        nonce = encryptor.getNonce()
        #här borde vi skicka med noncen i krypteringen
        encrypted_message = encryptor.encrypt2(message, key)
        sock.sendto(pickle.dumps(encrypted_message), (udp_host,udp_port))

        print(message)


if __name__ == '__main__':
    Main()