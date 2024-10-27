'''
Simple Client Data Transfer in the clear

In this example a connection is made between a client
and simple server running on the same machine over a 
pre-defined and agreed upon port.

This client application will transfer a simple text message
to the server.  The server will will simply display the contents  
of the message.

'''
#Craig Suhrke
#Assignment 11
#10/13/2024

import socket           # Import Python Standard Socket Library
import sys

print("Client Application")
print("Establish a connection to a server")
print("Available on the same host using PORT 5555")

PORT = 5555          # Port Number of Server
    
try:
    # Create a Socket
    clientSocket = socket.socket()
    
    # Get my local host address
    localHost = socket.gethostname()
    
    print("\nAttempt Connection to: ", localHost, PORT)
    
    clientSocket.connect((localHost, PORT))
    
    # Sending message if there was a connection
    print("Socket Connected ...")
    print("Sending Message to Server")
    
    while True:
        msg = input("Enter Message to Send or EXIT to End: ")
        messageBytes = bytes(str(msg).encode("utf-8"))
        clientSocket.sendall(messageBytes)
        buffer = clientSocket.recv(2048)
        stringBuffer = str(buffer)
        print("Your MD5 hashed message is " + stringBuffer)
        
    
    
except Exception as err:
    sys.exit(err)

            
