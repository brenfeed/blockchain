import os
import time
from binascii import hexlify, unhexlify
from hash import generate_prng, streebog_256
from signature import sign_message, p, q, a, bytes_to_int, int_to_bytes
from merkle import build_merkle_root

NAME = "Арсланбек"
SEED = "Арсланбек Картакаев"
TX_COUNT = 5
TX_SIZE = 200


def generate_transaction_data(index, prng_data):
    if index == 2:
        name_part = NAME.encode()
        random_part = prng_data[index + 1][:TX_SIZE - len(name_part)]
        return name_part + random_part
    else:
        return prng_data[index + 1][:TX_SIZE]


def main():
    prng_data = generate_prng(SEED, TX_COUNT + 3)

    private_key = bytes_to_int(prng_data[0]) % q
    nonces = [bytes_to_int(prng_data[i]) % q for i in range(1, TX_COUNT + 1)]

    os.makedirs("transactions", exist_ok=True)
    os.makedirs("signatures", exist_ok=True)

    transactions = []
    signatures = []
    public_keys = []

    for i in range(TX_COUNT):
        tx_data = generate_transaction_data(i, prng_data)
        transactions.append(tx_data)

        with open(f"transactions/tx{i + 1}.bin", "wb") as f:
            f.write(tx_data)

        e_val, s_val, y = sign_message(tx_data, private_key, nonces[i])
        signatures.append((e_val, s_val))
        public_keys.append(y)

        with open(f"signatures/tx{i + 1}.sig", "w") as f:
            f.write(f"e = {hex(e_val)}\n")
            f.write(f"s = {hex(s_val)}\n")
            f.write(f"y = {hex(y)}\n")

    leaf_data = [tx + int_to_bytes(sig[0], 32) + int_to_bytes(sig[1], 32)
                 for tx, sig in zip(transactions, signatures)]
    merkle_root = build_merkle_root(leaf_data)

    block_size = prng_data[TX_COUNT + 1][:4]
    prev_hash = prng_data[TX_COUNT + 2][:32]

    timestamp = time.localtime()
    ts_bytes = bytes([
        timestamp.tm_hour,
        timestamp.tm_mday,
        timestamp.tm_mon,
        timestamp.tm_year % 100
    ])

    for nonce in range(2 ** 32):
        nonce_bytes = nonce.to_bytes(4, 'big')
        header = block_size + prev_hash + merkle_root + ts_bytes + nonce_bytes
        header_hash = streebog_256(header)

        if header_hash[0] >> 3 == 0:
            print(f"Найден nonce: {nonce}")
            print(f"Хеш заголовка: {header_hash.hex()}")
            break
    else:
        print("Nonce не найден")


if __name__ == "__main__":
    main()