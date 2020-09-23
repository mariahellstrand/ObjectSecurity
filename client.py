import socket
import DH
import pickle



udp_host = socket.gethostname()		# Host IP
udp_port = 12345                    # specified port to connect

def startConnection(sock):
    print("starting a connection")
    # Starting Diffie Hellman handshake
    key = key_exchange(sock)
    print("Agreed shared key: ", key)
    print("Handshake done")

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
    


			        

#msg = "Hello Python!"
#print("UDP target IP:", udp_host)
#print("UDP target Port:", udp_port)

def menu():
    commands = ["s","q"]
    print("Type \'type\' to initiate handshake".replace('type', commands[0]))
    print("Type \'type\ to quit".replace('type', commands[1]))

#MAIN




def Main():
    sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)      # For UDP   

    print("choose what to do: ")
    COMMAND = input(": ")
    while COMMAND != "q":
        if COMMAND == "s":
            startConnection(sock)
        
        print("choose what to do: ")
        COMMAND = input(": ")
 
    #sock.sendto(msg.encode('utf-8'),(udp_host,udp_port))		# Sending message to UDP server

if __name__ == '__main__':
    Main()