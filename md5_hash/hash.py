from hashlib import md5


def hash_from_file(file):
    m = md5()
    with open(file, 'br') as b_file:
        data = b_file.read()
        m.update(data)
        hex_data = m.hexdigest()

        print(hex_data)  # 7705264ce6439c0074bc26dfaa374125 for current file
        print(m.digest_size)  # 16
        print(m.block_size)  # 64

        n = m.copy()
        print(n)  # <md5 HASH object @ 0x7f62c5ed3d50>


if __name__ == '__main__':
    hash_from_file('text.txt')
