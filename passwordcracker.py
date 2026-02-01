#!/usr/bin/env python3

import hashlib
import itertools
import sys
import argparse
import multiprocessing
import functools
import os
import string # <-- New import for charsets
from tqdm import tqdm
from functools import reduce # <-- New import for mask total

# --- HASHING ---
def hash_string(algorithm, text):
    """Hashes a string using the specified algorithm."""
    try:
        hasher = hashlib.new(algorithm)
        hasher.update(text.encode('utf-8'))
        return hasher.hexdigest()
    except ValueError:
        print(f"[!] Critical Error: Hash algorithm '{algorithm}' is not supported by hashlib.")
        print("Supported algorithms: md5, sha1, sha256, sha512, sha3_256, etc.")
        sys.exit(1)

# --- MASK ATTACK CONSTANTS & WORKER ---
CHARSET_L = string.ascii_lowercase
CHARSET_U = string.ascii_uppercase
CHARSET_D = string.digits
CHARSET_S = "!@#$%^&*()-_=+"

def mask_worker(candidate_tuple, target_hash, algorithm):
    """Worker for mask attack: joins tuple and checks hash."""
    attempt_text = "".join(candidate_tuple)
    attempt_hash = hash_string(algorithm, attempt_text)
    if attempt_hash == target_hash:
        return attempt_text
    return None

def parse_mask(mask):
    """Parses a mask string (e.g., '?u?l?l?d') into a list of charsets."""
    charsets = []
    i = 0
    while i < len(mask):
        if mask[i:i+2] == '?l':
            charsets.append(CHARSET_L)
            i += 2
        elif mask[i:i+2] == '?u':
            charsets.append(CHARSET_U)
            i += 2
        elif mask[i:i+2] == '?d':
            charsets.append(CHARSET_D)
            i += 2
        elif mask[i:i+2] == '?s':
            charsets.append(CHARSET_S)
            i += 2
        else: # Literal character
            charsets.append([mask[i]])
            i += 1
    return charsets

# --- RULE-BASED GENERATOR ---
def apply_rules(word):
    """Applies a set of transformation rules to a word."""
    yield word
    if word:
        yield word.capitalize()
    yield word.upper()
    for suffix in ['1', '123', '!', '2024', '2025']:
        yield word + suffix
    for prefix in ['!', '@', '#', '$']:
        yield prefix + word
    if 'e' in word or 'o' in word or 'a' in word:
        yield word.replace('e', '3').replace('o', '0').replace('a', '@')

# --- WORKER FOR BRUTE-FORCE ---
def brute_force_worker(length, target_hash, algorithm, charset):
    """Worker for brute-force: checks all combos for one length."""
    for attempt in itertools.product(charset, repeat=length):
        attempt_text = ''.join(attempt)
        attempt_hash = hash_string(algorithm, attempt_text)
        if attempt_hash == target_hash:
            return attempt_text
    return None

# --- WORKER FOR DICTIONARY / RULES ---
def dictionary_worker(word, target_hash, algorithm, apply_rules_flag):
    """Worker for dictionary: checks one word, with or without rules."""
    word = word.strip()
    if apply_rules_flag:
        for candidate in apply_rules(word):
            attempt_hash = hash_string(algorithm, candidate)
            if attempt_hash == target_hash:
                return candidate 
    else:
        attempt_hash = hash_string(algorithm, word)
        if attempt_hash == target_hash:
            return word
    return None

# --- FILE UTILITY ---
def get_line_count(filepath):
    """Utility to count lines in a file for the progress bar."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for i, _ in enumerate(f):
                pass
        return i + 1
    except FileNotFoundError:
        print(f"[!] Error: Dictionary file not found at {filepath}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error counting lines: {e}")
        sys.exit(1)

# --- MAIN EXECUTION ---
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="PyHashCracker - A high-performance, multi-threaded hash cracking tool.",
        epilog="--- Attack Mode Examples ---\n"
               "Brute-Force: python3 %(prog)s <hash> -a sha256 -b -c abc123 -l 6\n"
               "Dictionary:  python3 %(prog)s <hash> -a sha256 -d rockyou.txt\n"
               "Rule-Based:  python3 %(prog)s <hash> -a sha256 -d rockyou.txt -r\n"
               "Mask Attack: python3 %(prog)s <hash> -a md5 -m 'Pass?d?d?d?d'",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument("hash", help="The target hash to crack.")
    parser.add_argument("-a", "--algorithm", help="Hashing algorithm (e.g., md5, sha1, sha256)", required=True)

    # Attack modes are mutually exclusive
    attack_group = parser.add_mutually_exclusive_group(required=True)
    attack_group.add_argument("-b", "--bruteforce", action='store_true', help="Enable brute-force attack.")
    attack_group.add_argument("-d", "--dictionary", help="Enable dictionary attack. Provide path to wordlist.")
    attack_group.add_argument("-m", "--mask", help="Enable mask attack. (e.g., '?u?l?d?s')")

    # Brute-force specific arguments
    parser.add_argument("-c", "--charset", help="Character set for brute-force (e.g., 'abc123')")
    parser.add_argument("-l", "--max_length", type=int, help="Maximum password length for brute-force.")
    
    # Dictionary specific arguments
    parser.add_argument("-r", "--rules", action='store_true', help="Enable rule-based mutations. Use with -d.")

    args = parser.parse_args()
    args.algorithm = args.algorithm.lower()
    
    cpu_count = multiprocessing.cpu_count()
    found_password = None

    try:
        # --- MODE 1: BRUTE-FORCE ---
        if args.bruteforce:
            if not args.charset or not args.max_length:
                parser.error("Brute-force mode (-b) requires --charset (-c) and --max_length (-l).")
            
            print(f"--- Starting BRUTE-FORCE attack with {cpu_count} CPU cores ---")
            print(f"Target: {args.hash} ({args.algorithm})")
            print(f"Charset: {args.charset} | Max Length: {args.max_length}")

            lengths_to_check = range(1, args.max_length + 1)
            worker_func = functools.partial(brute_force_worker, target_hash=args.hash, algorithm=args.algorithm, charset=args.charset)
            
            with multiprocessing.Pool(processes=cpu_count) as pool:
                results_iterator = pool.imap_unordered(worker_func, lengths_to_check)
                pbar = tqdm(total=args.max_length, desc="Checking Lengths", unit="len")
                for result in results_iterator:
                    pbar.update(1)
                    if result:
                        found_password = result
                        pool.terminate()
                        break
                pbar.close()

        # --- MODE 2: DICTIONARY / RULES ---
        elif args.dictionary:
            if args.rules:
                print(f"--- Starting RULE-BASED DICTIONARY attack with {cpu_count} CPU cores ---")
            else:
                print(f"--- Starting STANDARD DICTIONARY attack with {cpu_count} CPU cores ---")
            
            print(f"Target: {args.hash} ({args.algorithm})")
            print(f"Wordlist: {args.dictionary}")
            
            line_count = get_line_count(args.dictionary)
            print(f"Total base words: {line_count:,}")

            worker_func = functools.partial(dictionary_worker, target_hash=args.hash, algorithm=args.algorithm, apply_rules_flag=args.rules)
            
            with open(args.dictionary, 'r', encoding='utf-8', errors='ignore') as f, \
                 multiprocessing.Pool(processes=cpu_count) as pool:
                
                chunksize = max(1000, line_count // (cpu_count * 4)) # Dynamic chunksize
                pbar = tqdm(total=line_count, desc="Cracking", unit="words")
                
                for result in pool.imap_unordered(worker_func, f, chunksize=chunksize):
                    pbar.update(1)
                    if result:
                        found_password = result
                        pool.terminate()
                        break
                pbar.close()
        
        # --- MODE 3: MASK ATTACK ---
        elif args.mask:
            print(f"--- Starting MASK attack with {cpu_count} CPU cores ---")
            print(f"Target: {args.hash} ({args.algorithm})")
            print(f"Mask: {args.mask}")
            
            try:
                parsed_charsets = parse_mask(args.mask)
                # Calculate total combinations for progress bar
                total_combinations = reduce(lambda x, y: x * len(y), parsed_charsets, 1)
                print(f"Total combinations: {total_combinations:,}")
            except Exception as e:
                print(f"[!] Error parsing mask: {e}")
                sys.exit(1)
                
            candidate_generator = itertools.product(*parsed_charsets)
            worker_func = functools.partial(mask_worker, target_hash=args.hash, algorithm=args.algorithm)
            
            with multiprocessing.Pool(processes=cpu_count) as pool:
                chunksize = max(1000, total_combinations // (cpu_count * 10))
                pbar = tqdm(total=total_combinations, desc="Cracking", unit="att")
                
                for result in pool.imap_unordered(worker_func, candidate_generator, chunksize=chunksize):
                    pbar.update(1)
                    if result:
                        found_password = result
                        pool.terminate()
                        break
                pbar.close()

    except KeyboardInterrupt:
        print("\n[!] Cracking stopped by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] An error occurred: {e}")
        sys.exit(1)

    # --- FINAL RESULT ---
    print("--- Attack finished ---")
    if found_password:
        print(f"\n[+] SUCCESS! Match found: {found_password}")
    else:
        print("\n[-] FAILED. No match found.")
