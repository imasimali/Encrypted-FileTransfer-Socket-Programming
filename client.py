import socket
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP

IP = socket.gethostbyname(socket.gethostname())
PORT = 4455
ADDR = (IP, PORT)
FORMAT = "utf-8"
SIZE = 1024
input_filename = "input.txt"
output_filename = "output.txt"

def main():
    """ Staring a TCP socket. """
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    """ Connecting to the server. """
    client.connect(ADDR)

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
            print('receiving')
            data = client.recv(32)
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

    """ Closing the connection from the server. """
    client.close()

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