import random

from win32 import win32crypt
from win32 import win32security

PROV_RSA_FULL = 1
PROV_RSA_AES = 24


def get_providers_list():
    providers = win32security.CryptEnumProviders()
    types = win32crypt.CryptEnumProviderTypes()

    print('\nProviders:\n')
    for l in providers:
        print(l)

    """
    ('Microsoft Base Cryptographic Provider v1.0', 1)
    ('Microsoft Base DSS and Diffie-Hellman Cryptographic Provider', 13)
    ('Microsoft Base DSS Cryptographic Provider', 3)
    ('Microsoft Base Smart Card Crypto Provider', 1)
    ('Microsoft DH SChannel Cryptographic Provider', 18)
    ('Microsoft Enhanced Cryptographic Provider v1.0', 1)
    ('Microsoft Enhanced DSS and Diffie-Hellman Cryptographic Provider', 13)
    ('Microsoft Enhanced RSA and AES Cryptographic Provider', 24)
    ('Microsoft RSA SChannel Cryptographic Provider', 12)
    ('Microsoft Strong Cryptographic Provider', 1)
    """

    for t in types:
        print(t)

    """
    ('RSA Full (Signature and Key Exchange)', 1)
    ('DSS Signature', 3)
    ('RSA SChannel', 12)
    ('DSS Signature with Diffie-Hellman Key Exchange', 13)
    ('Diffie-Hellman SChannel', 18)
    ('RSA Full and AES', 24)
    """


def crypt_get_random():
    rng = random.SystemRandom()
    print(rng.random())
    # 0.8770567782880151
    print(rng.randint(0, 100))
    # 30


if __name__ == '__main__':
    get_providers_list()
    crypt_get_random()
