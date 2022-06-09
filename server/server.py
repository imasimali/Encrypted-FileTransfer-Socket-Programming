from multiprocessing import connection
import socket
import os
from traceback import print_tb
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import threading
import hashlib
from Crypto import Random

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
        choice = connection.recv(SIZE).decode(FORMAT)
        if choice == "1":
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
            
            """ Deleting enc files """
            os.remove("bundle.enc")
            break

        if choice == "2":
            """ Generating RSA keys """
            random   = Random.new().read
            RSAkey   = RSA.generate(2048, random)
            public   = RSAkey.publickey().exportKey()
            private  = RSAkey.exportKey()

            """ Receiving the filename from the client. """
            print(f"[RECV] Receiving the filename.")
            filename = connection.recv(SIZE).decode(FORMAT)
            connection.send("Filename received.".encode(FORMAT))

            """ Sending Public Key to client """
            connection.send(public)
            print(f"[SERVER]: Public key sent")

            """ Receiving the file data from the server. """
            with open("rec.enc", "wb") as fw:
                print(f"[RECV] Receiving the file data.")
                while True:
                    print('Receiving data')
                    data = connection.recv(SIZE)
                    if data == b'BEGIN':
                        continue
                    elif data == b'ENDED':
                        print('Breaking from file write')
                        break
                    else:
                        fw.write(data)
                fw.close()
                print("Received..")
            msg = connection.recv(SIZE).decode(FORMAT)
            print(f"[SERVER]: {msg}")
    
            """ Decrypting the file with priv key. """
            d_file = decrypt("rec.enc", private, filename)
            print(f"[SERVER]: Recvd File Decrypted {d_file}")
            
            """ Deleting enc files """
            os.remove("rec.enc")

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

def decrypt(datafile, priv, filename):

    with open(datafile , 'rb') as f:
        e_aeskey = f.read(256)
        nonce = f.read(16)
        tag = f.read(16)
        e_data = f.read()

    privkey = RSA.importKey(priv)
    rsacipher = PKCS1_OAEP.new(privkey)

    aeskey = rsacipher.decrypt(e_aeskey)

    try:
        aescipher = AES.new(aeskey , AES.MODE_EAX , nonce)
        data = aescipher.decrypt_and_verify(e_data, tag)
    except:
        print("Decryption or Authenticity failure.")

    with open(filename , 'wb') as f:
        f.write(data)
    
    return filename

if __name__ == "__main__":
    main()