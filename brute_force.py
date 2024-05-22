#!/usr/bin/env python3

import hashlib
import itertools
import sys

def hash_string(algorithm, text):
    if algorithm == 'md5':
        return hashlib.md5(text.encode()).hexdigest()
    elif algorithm == 'sha1':
        return hashlib.sha1(text.encode()).hexdigest()
    elif algorithm == 'sha256':
        return hashlib.sha256(text.encode()).hexdigest()
    elif algorithm == 'sha3_256':
        return hashlib.sha3_256(text.encode()).hexdigest()
    else:
        raise ValueError('Unsupported algorithm.')

def brute_force_hash(target_hash, algorithm, charset, max_length):
    for length in range(1, max_length + 1):
        for attempt in itertools.product(charset, repeat=length):
            attempt_text = ''.join(attempt)
            attempt_hash = hash_string(algorithm, attempt_text)
            if attempt_hash == target_hash:
                return attempt_text
    return None

if __name__ == '__main__':
    if len(sys.argv) != 5:
        print(f"Usage: {sys.argv[0]} <hash> <algorithm> <charset> <max_length>")
        sys.exit(1)

    target_hash = sys.argv[1]
    algorithm = sys.argv[2].lower()
    charset = sys.argv[3]
    max_length = int(sys.argv[4])

    print(f"Brute-forcing {algorithm} hash: {target_hash}")
    print(f"Using charset: {charset}")
    print(f"Maximum length: {max_length}")

    result = brute_force_hash(target_hash, algorithm, charset, max_length)

    if result:
        print(f"Match found: {result}")
    else:
        print("No match found.")
