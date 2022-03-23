import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

IP = socket.gethostbyname(socket.gethostname())
PORT = 4455
ADDR = (IP, PORT)
SIZE = 1024
FORMAT = "utf-8"

def main():
    print("[STARTING] Server is starting.")
    """ Staring a TCP socket. """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    """ Bind the IP and PORT to the server. """
    server.bind(ADDR)

    """ Server is listening, i.e., server is now waiting for the client to connected. """
    server.listen()
    print("[LISTENING] Server is listening.")

    while True:
        """ Server has accepted the connection from the client. """
        conn, addr = server.accept()
        print(f"[NEW CONNECTION] {addr} connected.")

        """ Receiving the filename from the client. """
        print(f"[RECV] Receiving the filename.")
        filename = conn.recv(SIZE).decode(FORMAT)
        conn.send("Filename received.".encode(FORMAT))

        """ Reciving Public key from client """
        pubkey = conn.recv(SIZE).decode(FORMAT)
        print(f"[SERVER]: Public Key Rcvd")

        # """ Opening and reading the file data. """
        # file = open(filename, "r")
        # data = file.read()

        """ Encrypting the file before sending """
        e_file = encryption(pubkey ,filename)

        """ Sending the file data to the server. """
        print(f"[SEND] Sending the file data.")
        conn.send(e_file.encode(FORMAT))
        conn.send("File data received".encode(FORMAT))
        
        # """ Closing the file. """
        # file.close()

        """ Closing the connection from the client. """
        conn.close()
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