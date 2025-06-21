import struct
from binascii import hexlify, unhexlify

BLOCK_SIZE = 64

PI = [
    252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77,
    233, 119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193,
    249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79,
    5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31,
    235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204,
    181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135,
    21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177,
    50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87,
    223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3,
    224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74,
    167, 151, 96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65,
    173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59,
    7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137,
    225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97,
    32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82,
    89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182
]

TAU = [
    0, 8, 16, 24, 32, 40, 48, 56,
    1, 9, 17, 25, 33, 41, 49, 57,
    2, 10, 18, 26, 34, 42, 50, 58,
    3, 11, 19, 27, 35, 43, 51, 59,
    4, 12, 20, 28, 36, 44, 52, 60,
    5, 13, 21, 29, 37, 45, 53, 61,
    6, 14, 22, 30, 38, 46, 54, 62,
    7, 15, 23, 31, 39, 47, 55, 63
]

A = [
    0x8e20faa72ba0b470, 0x47107ddd9b505a38, 0xad08b0e0c3282d1c, 0xd8045870ef14980e,
    0x6c022c38f90a4c07, 0x3601161cf205268d, 0x1b8e0b0e798c13c8, 0x83478b07b2468764,
    0xa011d380818e8f40, 0x5086e740ce47c920, 0x2843fd2067adea10, 0x14aff010bdd87508,
    0x0ad97808d06cb404, 0x05e23c0468365a02, 0x8c711e02341b2d01, 0x46b60f011a83988e,
    0x90dab52a387ae76f, 0x486dd4151c3dfdb9, 0x24b86a840e90f0d2, 0x125c354207487869,
    0x092e94218d243cba, 0x8a174a9ec8121e5d, 0x4585254f64090fa0, 0xaccc9ca9328a8950,
    0x9d4df05d5f661451, 0xc0a878a0a1330aa6, 0x60543c50de970553, 0x302a1e286fc58ca7,
    0x18150f14b9ec46dd, 0x0c84890ad27623e0, 0x0642ca05693b9f70, 0x0321658cba93c138,
    0x86275df09ce8aaa8, 0x439da0784e745554, 0xafc0503c273aa42a, 0xd960281e9d1d5215,
    0xe230140fc0802984, 0x71180a8960409a42, 0xb60c05ca30204d21, 0x5b068c651810a89e,
    0x456c34887a3805b9, 0xac361a443d1c8cd2, 0x561b0d22900e4669, 0x2b838811480723ba,
    0x9bcf4486248d9f5d, 0xc3e9224312c8c1a0, 0xeffa11af0964ee50, 0xf97d86d98a327728,
    0xe4fa2054a80b329c, 0x727d102a548b194e, 0x39b008152acb8227, 0x9258048415eb419d,
    0x492c024284fbaec0, 0xaa16012142f35760, 0x550b8e9e21f7a530, 0xa48b474f9ef5dc18,
    0x70a6a56e2440598e, 0x3853dc371220a247, 0x1ca76e95091051ad, 0x0edd37c48a08a6d8,
    0x07e095624504536c, 0x8d70c431ac02a736, 0xc83862965601dd1b, 0x641c314b2b8ee083
]

C = [
    unhexlify(b"b1085bda1ecadae9ebcb2f81c0657c1f2f6a76432e45d016714eb88d7585c4fc"
              b"4b7ce09192676901a2422a08a460d31505767436cc744d23dd806559f2a64507"),
    unhexlify(b"6fa3b58aa99d2f1a4fe39d460f70b5d7f3feea720a232b9861d55e0f16b50131"
              b"9ab5176b12d699585cb561c2db0aa7ca55dda21bd7cbcd56e679047021b19bb7"),
    unhexlify(b"f574dcac2bce2fc70a39fc286a3d843506f15e5f529c1f8bf2ea7514b1297b7b"
              b"d3e20fe490359eb1c1c93a376062db09c2b6f443867adb31991e96f50aba0ab2"),
    unhexlify(b"ef1fdfb3e81566d2f948e1a05d71e4dd488e857e335c3c7d9d721cad685e353f"
              b"a9d72c82ed03d675d8b71333935203be3453eaa193e837f1220cbebc84e3d12e"),
    unhexlify(b"4bea6bacad4747999a3f410c6ca923637f151c1f1686104a359e35d7800fffbd"
              b"bfcd1747253af5a3dfff00b723271a167a56a27ea9ea63f5601758fd7c6cfe57"),
    unhexlify(b"ae4faeae1d3ad3d96fa4c33b7a3039c02d66c4f95142a46c187f9ab49af08ec6"
              b"cffaa6b71c9ab7b40af21f66c2bec6b6bf71c57236904f35fa68407a46647d6e"),
    unhexlify(b"f4c70e16eeaac5ec51ac86febf240954399ec6c7e6bf87c9d3473e33197a93c9"
              b"0992abc52d822c3706476983284a05043517454ca23c4af38886564d3a14d493"),
    unhexlify(b"9b1f5b424d93c9a703e7aa020c6e41414eb7f8719c36de1e89b4443b4ddbc49a"
              b"f4892bcb929b069069d18d2bd1a5c42f36acc2355951a8d9a47f0dd4bf02e71e"),
    unhexlify(b"378f5a541631229b944c9ad8ec165fde3a7d3a1b258942243cd955b7e00d0984"
              b"800a440bdbb2ceb17b2b8a9aa6079c540e38dc92cb1f2a607261445183235adb"),
    unhexlify(b"abbedea680056f52382ae548b2e4f3f38941e71cff8a78db1fffe18a1b336103"
              b"9fe76702af69334b7a1e6c303b7652f43698fad1153bb6c374b4c7fb98459ced"),
    unhexlify(b"7bcd9ed0efc889fb3002c6cd635afe94d8fa6bbbebab07612001802114846679"
              b"8a1d71efea48b9caefbacd1d7d476e98dea2594ac06fd85d6bcaa4cd81f32d1b"),
    unhexlify(b"378ee767f11631bad21380b00449b17acda43c32bcdf1d77f82012d430219f9b"
              b"5d80ef9d1891cc86e71da4aa88e12852faf417d5d9b21b9948bc924af11bd720")
]


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def s_box(data):
    return bytes(PI[b] for b in data)


def p_trans(data):
    return bytes(data[TAU[i]] for i in range(64))


def l_transform(data):
    result = bytearray(64)
    for i in range(8):
        value = struct.unpack('<Q', data[i * 8:i * 8 + 8])[0]
        res = 0
        for j in range(64):
            if value & (1 << (63 - j)):
                res ^= A[j]
        result[i * 8:i * 8 + 8] = struct.pack('<Q', res)
    return bytes(result)


def lps(data):
    return l_transform(p_trans(s_box(data)))


def e(key, message):
    state = message
    for i in range(12):
        state = lps(xor_bytes(key, state))
        key = lps(xor_bytes(key, C[i]))
    return xor_bytes(key, state)


def add_512(a, b):
    res = bytearray(64)
    carry = 0
    for i in range(64):
        carry += a[i] + b[i]
        res[i] = carry & 0xFF
        carry >>= 8
    return bytes(res)


def g(n, h, m):
    k = lps(xor_bytes(h, n))
    e_val = e(k, m)
    return xor_bytes(xor_bytes(e_val, h), m)


def streebog_256(data):
    h = b'\x01' * 64
    sigma = b'\x00' * 64
    length = 0

    for i in range(0, len(data) - 63, 64):
        block = data[i:i + 64]
        h = g(length.to_bytes(64, 'big'), h, block)
        sigma = add_512(sigma, block)
        length += 512

    last_block = data[-(len(data) % 64):] if len(data) % 64 != 0 else b''
    pad_length = 64 - len(last_block)
    padded = last_block + b'\x80' + b'\x00' * (pad_length - 1)

    h = g(length.to_bytes(64, 'big'), h, padded)
    sigma = add_512(sigma, padded)
    length += len(last_block) * 8

    h = g(b'\x00' * 64, h, length.to_bytes(64, 'big'))
    h = g(b'\x00' * 64, h, sigma)

    return h[:32]

def streebog_512(data):
    h = b'\x00' * 64
    sigma = b'\x00' * 64
    length = 0

    for i in range(0, len(data) - 63, 64):
        block = data[i:i + 64]
        h = g(length.to_bytes(64, 'big'), h, block)
        sigma = add_512(sigma, block)
        length += 512

    last_block = data[-(len(data) % 64):] if len(data) % 64 != 0 else b''
    pad_length = 64 - len(last_block)
    padded = last_block + b'\x80' + b'\x00' * (pad_length - 1)

    h = g(length.to_bytes(64, 'big'), h, padded)
    sigma = add_512(sigma, padded)
    length += len(last_block) * 8

    h = g(b'\x00' * 64, h, length.to_bytes(64, 'big'))
    h = g(b'\x00' * 64, h, sigma)

    return h


def generate_prng(seed, count, digest_size=256):
    results = []
    h0 = streebog_256(seed.encode()) if digest_size == 256 else streebog_512(seed.encode())
    for i in range(count):
        data = h0 + struct.pack('>H', i)
        hi = streebog_256(data) if digest_size == 256 else streebog_512(data)
        results.append(hi)
    return results