from hash import streebog_256

p = 0xEE8172AE8996608FB69359B89EB82A69854510E2977A4D63BC97322CE5DC3386EA0A12B343E9190F23177539845839786BB0C345D165976EF2195EC9B1C379E3
q = 0x98915E7EC8265EDFCDA31E88F24809DDB064BDC7285DD50D7289F0AC6F49DD2D
a = 0x9E96031500C8774A869582D4AFDE2127AFAD2538B4B6270A6F7C8837B50D50F206755984A49E509304D648BE2AB5AAB18EBE2CD46AC3D8495B142AA6CE23E21C


def bytes_to_int(b):
    return int.from_bytes(b, 'big')


def int_to_bytes(x, size):
    return x.to_bytes(size, 'big')


def sign_message(message, private_key, nonce):
    y = pow(a, private_key, p)
    y_bytes = int_to_bytes(y, (p.bit_length() + 7) // 8)

    r = pow(a, nonce, p)
    r_bytes = int_to_bytes(r, (p.bit_length() + 7) // 8)

    hash_input = y_bytes + r_bytes + message
    e_hash = streebog_256(hash_input)
    e_val = bytes_to_int(e_hash) % q

    s_val = (nonce + private_key * e_val) % q

    return e_val, s_val, y


def verify_signature(message, signature, public_key):
    e_val, s_val = signature
    y_inv = pow(public_key, -e_val, p)
    r_prime = (pow(a, s_val, p) * y_inv) % p
    r_prime_bytes = int_to_bytes(r_prime, (p.bit_length() + 7) // 8)

    y_bytes = int_to_bytes(public_key, (p.bit_length() + 7) // 8)
    hash_input = y_bytes + r_prime_bytes + message
    e_prime = bytes_to_int(streebog_256(hash_input)) % q

    return e_val == e_prime