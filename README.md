# Authenticated and Encrypted FileTransfer using Socket Programming

User can create a new account or log in to an existing account.

User can upload or download a file from the Server.

An RSA public key is sent to the sender. The file being uploaded/downloaded is encrypted through AES encryption. Then received RSA public key is used to encrypt the AES key.

The encrypted file and key is transferred to the receiver. The receiver then uses his RSA private key to unlock the AES key and then decrypt the file using that key.

#### These Client & Server Programs are written from scratch using python in-build socket libraries. This uses multi-threading to handle multiple clients efficiently.
