from distutils.command.clean import clean
import socket
import os
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

IP = socket.gethostbyname(socket.gethostname())
PORT = 4455
ADDR = (IP, PORT)
FORMAT = "utf-8"
SIZE = 1024
input_filename = "hawk.png"
output_filename = "output.png"

def main():
    """ Staring a TCP socket. """
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    """ Connecting to the server. """
    client.connect(ADDR)

    """ Authenticating with client """
    response = client.recv(2048)
    # Input UserName
    name = input(response.decode())	
    client.send(str.encode(name))
    response = client.recv(2048)
    # Input Password
    password = input(response.decode())	
    client.send(str.encode(password))
    ''' Response : Status of Connection :
        1 : Registeration successful 
        2 : Connection Successful
        3 : Login Failed
    '''
    # Receive response 
    msg = client.recv(2048).decode(FORMAT)
    print(f"[SERVER]: {msg}")

    if msg == "Login Failed":
        client.close()
        return

    """ Choice to upload or download """
    print(''' Press Key : Operation performed :
        1 : Download File 
        2 : Upload File
        3 : Exit
    ''')
    choice = input("OPTION: ")
    client.send(choice.encode(FORMAT))

    if choice == "1":
        """ Generating RSA keys """
        random   = Random.new().read
        RSAkey   = RSA.generate(2048, random)
        public   = RSAkey.publickey().exportKey()
        private  = RSAkey.exportKey()

        """ Sending the input_filename to the server. """
        client.send(input_filename.encode(FORMAT))
        msg = client.recv(SIZE).decode(FORMAT)
        print(f"[SERVER]: {msg}")

        """ Sending Public Key to server """
        client.send(public)
        print(f"[CLIENT]: Public key sent")

        """ Receiving the file data from the server. """
        with open("rec.enc", "wb") as fw:
            print(f"[RECV] Receiving the file data.")
            while True:
                print('Receiving data')
                data = client.recv(SIZE)
                if data == b'BEGIN':
                    continue
                elif data == b'ENDED':
                    print('Breaking from file write')
                    break
                else:
                    fw.write(data)
            fw.close()
            print("Received..")
        msg = client.recv(SIZE).decode(FORMAT)
        print(f"[CLIENT]: {msg}")

        """ Decrypting the file with priv key. """
        d_file = decrypt("rec.enc", private)
        print(f"[CLIENT]: Recvd File Decrypted {d_file}")

        """ Deleting enc files """
        os.remove("rec.enc")

    if choice == "2":
        """ Sending the output_filename to the server. """
        client.send(output_filename.encode(FORMAT))
        msg = client.recv(SIZE).decode(FORMAT)
        print(f"[CLIENT]: {msg}")

        """ Reciving Public key from server """
        pubkey = client.recv(SIZE).decode(FORMAT)
        print(f"[CLIENT]: Public Key Rcvd")

        """ Encrypting the file before sending """
        e_file = encryption(pubkey ,output_filename)

        """ Opening and reading the file data & Sending the file data to the server. """
        print(f"[SEND] Sending the file data.")
        with open(e_file, 'rb') as fs:
            client.send(b'BEGIN')
            while True:
                data = fs.read(SIZE)
                client.send(data)
                if not data:
                    print('Breaking from sending data')
                    break
            client.send(b'ENDED') # I used the same size of the BEGIN token
            fs.close()
        client.send("File data received".encode(FORMAT))

        """ Deleting enc files """
        os.remove("bundle.enc")

    else:
        """ Closing the connection from the server. """
        client.close()

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

def decrypt(datafile, priv):

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

    with open(output_filename , 'wb') as f:
        f.write(data)
    
    return output_filename

if __name__ == "__main__":
    main()