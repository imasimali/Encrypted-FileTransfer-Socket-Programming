from multiprocessing import connection
import socket
from traceback import print_tb
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import threading
import hashlib

IP = socket.gethostbyname(socket.gethostname())
PORT = 4455
ADDR = (IP, PORT)
SIZE = 1024
FORMAT = "utf-8"
HASHTABLE = {}

def main():
    print("[STARTING] Server is starting.")
    """ Staring a TCP socket. """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    """ Bind the IP and PORT to the server. """
    server.bind(ADDR)

    """ Server is listening, i.e., server is now waiting for the client to connected. """
    server.listen()
    print("[LISTENING] Server is listening.")
    ThreadCount = 0

    while True:
        """ Server has accepted the connection from the client. """
        connection, addr = server.accept()
        print(f"[NEW CONNECTION] {addr} connected.")

        """" User Auth Setup with Threading """
        client_handler = threading.Thread(
            target=threaded_client,
            args=(connection, addr)  
        )
        client_handler.start()
        ThreadCount += 1
        print('Connection Request: ' + str(ThreadCount))


def threaded_client(connection, addr):
    connection.send(str.encode('ENTER USERNAME : ')) # Request Username
    name = connection.recv(2048)
    connection.send(str.encode('ENTER PASSWORD : ')) # Request Password
    password = connection.recv(2048)
    password = password.decode()
    name = name.decode()
    password=hashlib.sha256(str.encode(password)).hexdigest() # Password hash using SHA256
    # REGISTERATION PHASE   
    # If new user,  regiter in HASHTABLE Dictionary  
    if name not in HASHTABLE:
        HASHTABLE[name]=password
        connection.send(str.encode('Registeration Successful')) 
        print('Registered : ',name)
        print("{:<8} {:<20}".format('USER','PASSWORD'))
        for k, v in HASHTABLE.items():
            label, num = k,v
            print("{:<8} {:<20}".format(label, num))
        print("-------------------------------------------")

    else:
    # If already existing user, check if the entered password is correct
        if(HASHTABLE[name] == password):
            connection.send(str.encode('Connection Successful')) # Response Code for Connected Client 
            print('Connected : ',name)
        else:
            connection.send(str.encode('Login Failed')) # Response code for login failed
            print('Connection denied : ',name)
            connection.close()
            return

    while True:
        """ Receiving the filename from the client. """
        print(f"[RECV] Receiving the filename.")
        filename = connection.recv(SIZE).decode(FORMAT)
        connection.send("Filename received.".encode(FORMAT))

        """ Reciving Public key from client """
        pubkey = connection.recv(SIZE).decode(FORMAT)
        print(f"[SERVER]: Public Key Rcvd")

        """ Encrypting the file before sending """
        e_file = encryption(pubkey ,filename)

        """ Opening and reading the file data & Sending the file data to the client. """
        print(f"[SEND] Sending the file data.")
        with open(e_file, 'rb') as fs:
            connection.send(b'BEGIN')
            while True:
                data = fs.read(SIZE)
                connection.send(data)
                if not data:
                    print('Breaking from sending data')
                    break
            connection.send(b'ENDED') # I used the same size of the BEGIN token
            fs.close()
        connection.send("File data received".encode(FORMAT))
        break
    
    """ Closing the connection from the client. """
    connection.close()
    print(f"[DISCONNECTED] {addr} disconnected.")


def encryption(pubkey, datafile):
    aeskey = get_random_bytes(16)

    rsakey = RSA.importKey(pubkey)
    rsacipher = PKCS1_OAEP.new(rsakey)
    e_aeskey = rsacipher.encrypt(aeskey)
    
    with open(datafile , 'rb') as f:
        data = f.read()

    aescipher = AES.new(aeskey, AES.MODE_EAX)
    e_data , tag = aescipher.encrypt_and_digest(data)

    with open('bundle.enc' , 'wb') as f:
        f.write(e_aeskey)
        f.write(aescipher.nonce)
        f.write(tag)
        f.write(e_data)

    return 'bundle.enc'

if __name__ == "__main__":
    main()