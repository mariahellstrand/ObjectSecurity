# ObjectSecurity

A project in the course EITN50 - Advanced Computer Security

In this project we have set up a secure UDP connection between a server and a client following the principle of object security. Since UDP does not have the same security features as TCP, a secure implementation of authentication and encryption was needed. 

The implementation of this project contains of a client and a server, the senders and receivers of data. In order to start a secure session between the client and the server a handshake is performed which uses Diffie-Hellman to create a shared ephemeral key. When performing encryption Advanced Encryption Standard (AES) is used together with the shared ephermal key. To protect against integrity attacks a HMAC, calculated on the encrypted message, is used to verify the integrity of the message. The calculation of nonces are used in order to establish protection against replay-attacks of an ongoing session.

## Before you run the code ##
The following python packages needs to be installed:

$ **pip3 install pyCrypto**

$ **pip3 install pickle**

## How to run the code
To set up a connection between server and client the following commands is required: 

*Observ that the server has to be started before the client*

$ **python3 server.py**

$ **python3 client.py**

