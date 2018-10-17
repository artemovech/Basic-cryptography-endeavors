from Crypto import Random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5


class DigitalSignature:
    '''
    Class provides methods for Alice-Bob communication using digital signature


    '''

    def alice_generate_keys(self):
        # keys generator
        privatekey = RSA.generate(2048)  # Alice private key
        publickey = privatekey.publickey()  # Alice public key

        with open('alice_private_key.txt', 'wb') as f:
            f.write(bytes(privatekey.exportKey('PEM')))

        with open('alice_public_key.txt', 'wb') as f:
            f.write(bytes(publickey.exportKey('PEM')))

        privatekey = RSA.generate(2048)  # Bob private key
        publickey = privatekey.publickey()  # Bob public key

        with open('bob_private_key.txt', 'wb') as f:
            f.write(bytes(privatekey.exportKey('PEM')))

        with open('bob_public_key.txt', 'wb') as f:
            f.write(bytes(publickey.exportKey('PEM')))

    def alice_add_signature(self):
        # signature creation
        with open('text.txt', 'rb') as f:
            plaintext = f.read()  # get secret message

        privatekey = RSA.importKey(open('alice_private_key.txt', 'rb').read())  # get Alice private key
        myhash = SHA.new(plaintext)  # hash secret message

        # RSA digital signature protocol according to PKCS#1 v1.5
        signature = PKCS1_v1_5.new(privatekey)  # create digital signature.
        signature = signature.sign(myhash)  # Alice sign message
        publickey = RSA.importKey(open('bob_public_key.txt', 'rb').read())  # get Bob public key

        # RSA encryption protocol according to PKCS#1 OAEP
        rsa_chipher = PKCS1_OAEP.new(publickey)  #
        rsa_signature = rsa_chipher.encrypt(signature[:128]) + rsa_chipher.encrypt(
            signature[128:])  # ALice encrypt signature

        with open('signature.txt', 'wb') as f:  # save our signature
            f.write(bytes(rsa_signature))

    def alice_generate_session_key(self):
        session_key = Random.new().read(32)  # create session key 256 bit

        with open('text.txt', 'rb') as f:
            plaintext = f.read()

        # Aice takes session_key and encrypts secret message

        iv = Random.new().read(16)  # Initialization vector (IV)
        obj = AES.new(session_key, AES.MODE_CFB, iv)  # CFB
        cipher_text = iv + obj.encrypt(plaintext)
        with open('text_encrypted.txt', 'wb') as f:
            f.write(bytes(cipher_text))  # save cipher_text

        # RSA encryption for session key

        publickey = RSA.importKey(open('bob_public_key.txt', 'rb').read())  # get Bob's public key
        rsa_chipher = PKCS1_OAEP.new(publickey)
        session_key = rsa_chipher.encrypt(session_key)  # encrypt session key by Bob's public key

        with open('session_key.txt', 'wb') as f:
            f.write(bytes(session_key))  # save session key

    def bob_decrypt_session_key(self):
        # decrypt session_key
        privatekey = RSA.importKey(open('bob_private_key.txt', 'rb').read())
        cipherrsa = PKCS1_OAEP.new(privatekey)

        with open('session_key.txt', 'rb') as f:
            sessionkey = f.read()

        self.sessionkey = cipherrsa.decrypt(sessionkey)

    def bob_decrypt_message(self):
        # decrypt message

        with open('text_encrypted.txt', 'rb') as f:
            ciphertext = f.read()

        iv = ciphertext[:16]
        obj = AES.new(self.sessionkey, AES.MODE_CFB, iv)  # CFB
        plaintext = obj.decrypt(ciphertext)  # decrypt secret message
        plaintext = plaintext[16:]

        with open('text_decrypted.txt', 'wb') as f:
            f.write(bytes(plaintext))

    def bob_check_alice_signature(self):
        # decryption signature
        with open('signature.txt', 'rb') as f:
            signature = f.read()

        privatekey = RSA.importKey(open('bob_private_key.txt', 'rb').read())
        cipherrsa = PKCS1_OAEP.new(privatekey)
        sig = cipherrsa.decrypt(signature[:256]) + cipherrsa.decrypt(signature[256:])

        with open('text_decrypted.txt', 'rb') as f:
            plaintext = f.read()

        publickey = RSA.importKey(open('alice_public_key.txt', 'rb').read())
        myhash = SHA.new(plaintext)
        signature = PKCS1_v1_5.new(publickey)

        test = signature.verify(myhash, sig)  # verify signature
        print(test)  # True


if __name__ == '__main__':
    d = DigitalSignature()

    d.alice_generate_keys()
    d.alice_add_signature()
    d.alice_generate_session_key()

    d.bob_decrypt_session_key()
    d.bob_decrypt_message()
    d.bob_check_alice_signature()
