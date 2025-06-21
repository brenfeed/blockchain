from hash import streebog_256
import os


def hash_leaf(data):
    return streebog_256(data)


def hash_internal(left, right):
    return streebog_256(left + right)


def build_merkle_root(transactions):
    if not transactions:
        return b''

    level = [hash_leaf(tx) for tx in transactions]

    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                next_level.append(hash_internal(level[i], level[i + 1]))
            else:
                next_level.append(hash_internal(level[i], level[i]))
        level = next_level

    return level[0]