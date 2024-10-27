'''
Simple Server to receive data from client
NOTE: SERVER MUST BE STARTED AS ADMIN

In this example a connection is made between a client
and simple server running on the same machine over a 
pre-defined and agreed upon port.

This server application will wait for a connection request
over a pre-defined port.

Once a connection is established the server will receive data sent 
over the port and display the contents of the recevied data.

'''

import socket       # import Python Standard Socket Library
import sys
import hashlib

print("Server Starting up\n")
    
try: 
    
    serverSocket = socket.socket()      # Create Socket for listening
    
    localHost = socket.gethostname()    # Get my local host address
    
    localPort = 5555                    # Specify a local Port 
                                        # to accept connections on
    
    serverSocket.bind((localHost, localPort))  # Bind mySocket to localHost
    
    serverSocket.listen(1)              # Listen for connections

    print('\nWaiting for Connection Request')    
    
    ''' Wait for a connection request
        Note this is a synchronous Call meaning the program will halt until
        a connection is received.  Once a connection is received
        we will accept the connection and obtain the 
        ipAddress of the connecting computer
    '''
    
    conn, client = serverSocket.accept()
    
    
    print("Connection Received from Client: ", conn, client)
    
    while True:
        buffer = conn.recv(2048)  # Wait for Data
        print(buffer)
        md5Hash = hashlib.md5(buffer)
        hashDigest = md5Hash.hexdigest()
        messageBytes = bytes(str(hashDigest).encode("utf-8"))
        conn.send(messageBytes) 
        if b'exit' in buffer.lower():
            print("Server Terminated by User")
            break
    
except Exception as err:
    sys.exit(str(err))

