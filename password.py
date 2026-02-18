#!/usr/bin/env python3

import hashlib
import itertools
import sys
import argparse
import multiprocessing
import functools
import os
import string
import binascii
import hmac
import time
import math
from tqdm import tqdm
from datetime import datetime

# --- OPTIONAL IMPORTS ---
try:
    import bcrypt
    HAS_BCRYPT = True
except ImportError:
    HAS_BCRYPT = False

try:
    import crypt
    HAS_CRYPT = True
except ImportError:
    HAS_CRYPT = False

# --- CONFIGURATION ---
DEFAULT_THREADS = 4
MAX_PASSWORD_LENGTH = 64

# --- UI & COLORS ---
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    PURPLE = '\033[35m'
    YELLOW = '\033[33m'

def print_banner():
    if os.name == 'nt': 
        os.system('cls')
    else: 
        os.system('clear')
    
    banner = f"""{Colors.CYAN}
    ╔══════════════════════════════════════════════════════════════════════════════════╗
    ║                     H A S H C R A C K E R  v2.0                               ║
    ║     {Colors.HEADER}Advanced Password Recovery Tool | Multi-Attack Modes | Fast & Efficient{Colors.CYAN}  ║
    ╚══════════════════════════════════════════════════════════════════════════════════╝
    
    {Colors.PURPLE}Attack Modes:{Colors.ENDC}
    {Colors.YELLOW}├──{Colors.ENDC} Dictionary Attack (Default)
    {Colors.YELLOW}├──{Colors.ENDC} Mask Attack (?l?l?l?l?d?d for lowercase+digits)
    {Colors.YELLOW}├──{Colors.ENDC} Combination Attack (Wordlist + Wordlist)
    {Colors.YELLOW}├──{Colors.ENDC} Hybrid Attack (Wordlist + Mask / Mask + Wordlist)
    {Colors.YELLOW}└──{Colors.ENDC} Brute-force (Automatic)
    
    {Colors.BLUE}Example:{Colors.ENDC} python3 password.py -m 0 -a 3 --mask "?l?l?l?d?d?d?s" 5d41402abc4b2a76b9719d911017c592
    """
    print(banner)

def print_info(key, value):
    print(f"{Colors.BLUE}[*] {key:<20}: {Colors.ENDC}{value}")

def print_success(password, mode="Dictionary", time_taken=0, attempts=0, salt=None):
    print(f"\n{'═'*70}")
    print(f"{Colors.GREEN}{Colors.BOLD}╔═══════════════════════════════════════════════════════════════════╗")
    print(f"║                     PASSWORD FOUND!                           ║")
    print(f"╚═══════════════════════════════════════════════════════════════════╗")
    print(f"║ {Colors.CYAN}Hash:     {Colors.ENDC}{password:<54} ║")
    print(f"║ {Colors.CYAN}Mode:     {Colors.ENDC}{mode:<54} ║")
    if time_taken:
        print(f"║ {Colors.CYAN}Time:     {Colors.ENDC}{time_taken:.2f} seconds{Colors.ENDC}{' '*(54-len(str(time_taken)))} ║")
    if attempts:
        print(f"║ {Colors.CYAN}Attempts: {Colors.ENDC}{attempts:,}{Colors.ENDC}{' '*(54-len(str(attempts)))} ║")
    if salt:
        salt_display = salt[:50] + "..." if len(salt) > 50 else salt
        print(f"║ {Colors.CYAN}Salt:     {Colors.ENDC}{salt_display:<54} ║")
    print(f"╚═══════════════════════════════════════════════════════════════════╝{Colors.ENDC}\n")

def print_stats(start_time, end_time, total_attempts, speed):
    print(f"\n{Colors.CYAN}{'─'*60}")
    print(f"Session Statistics:")
    print(f"  Time Elapsed:    {end_time - start_time:.2f} seconds")
    print(f"  Total Attempts:  {total_attempts:,}")
    print(f"  Average Speed:   {speed:,.0f} hashes/sec")
    print(f"{'─'*60}{Colors.ENDC}")

# --- CHARACTER SETS FOR MASK ATTACK ---
CHAR_SETS = {
    '?l': string.ascii_lowercase,          # abcdefghijklmnopqrstuvwxyz
    '?u': string.ascii_uppercase,          # ABCDEFGHIJKLMNOPQRSTUVWXYZ
    '?d': string.digits,                   # 0123456789
    '?s': string.punctuation,              # !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
    '?a': string.ascii_letters + string.digits + string.punctuation,  # All printable
    '?h': string.hexdigits.lower(),        # 0123456789abcdef
    '?H': string.hexdigits.upper(),        # 0123456789ABCDEF
    '?n': string.digits + string.ascii_letters,  # Alphanumeric
}

# --- ATTACK MODES ---
class AttackModes:
    STRAIGHT = 0      # Dictionary attack
    COMBINATION = 1   # Combine two wordlists
    MASK = 3          # Mask attack (brute-force with pattern)
    HYBRID_WORDLIST_MASK = 6  # Wordlist + Mask
    HYBRID_MASK_WORDLIST = 7  # Mask + Wordlist
    
    @staticmethod
    def get_mode_name(mode):
        names = {
            0: "Dictionary Attack",
            1: "Combination Attack",
            3: "Mask Attack",
            6: "Hybrid (Wordlist+Mask)",
            7: "Hybrid (Mask+Wordlist)"
        }
        return names.get(mode, "Unknown")

# --- PASSWORD GENERATORS FOR DIFFERENT ATTACK MODES ---

def mask_generator(mask):
    """Generate passwords based on mask pattern"""
    charsets = []
    i = 0
    while i < len(mask):
        if i + 1 < len(mask) and mask[i] == '?' and mask[i+1] in 'ludsahnH':
            charsets.append(CHAR_SETS[mask[i:i+2]])
            i += 2
        else:
            # Fixed character
            charsets.append(mask[i])
            i += 1
    
    # Generate all combinations
    for combo in itertools.product(*charsets):
        yield ''.join(combo)

def combination_generator(wordlist1, wordlist2):
    """Generate combinations from two wordlists"""
    with open(wordlist1, 'r', encoding='utf-8', errors='ignore') as f1:
        words1 = [line.strip() for line in f1 if line.strip()]
    
    with open(wordlist2, 'r', encoding='utf-8', errors='ignore') as f2:
        for line2 in f2:
            word2 = line2.strip()
            if not word2:
                continue
            for word1 in words1:
                yield word1 + word2

def hybrid_generator(wordlist, mask, prepend=False):
    """Generate hybrid passwords (wordlist + mask or mask + wordlist)"""
    with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            word = line.strip()
            if not word:
                continue
            
            # Generate mask combinations
            mask_combinations = list(mask_generator(mask))
            for mask_word in mask_combinations:
                if prepend:
                    yield mask_word + word
                else:
                    yield word + mask_word

def brute_force_generator(min_len=1, max_len=6, charset=string.ascii_letters + string.digits):
    """Brute-force generator"""
    for length in range(min_len, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            yield ''.join(combo)

# --- ALGORITHM FACTORY ---
# [Keep all the existing algorithm functions - they remain the same]
def algo_md5(p, s=None): return hashlib.md5(p).hexdigest()
def algo_md5_salt(p, s): return hashlib.md5((p + s)).hexdigest()
def algo_salt_md5(p, s): return hashlib.sha1((s + p)).hexdigest()
def algo_md5_double(p, s=None): return hashlib.md5(hashlib.md5(p).digest()).hexdigest()
def algo_sha1(p, s=None): return hashlib.sha1(p).hexdigest()
def algo_sha1_salt(p, s): return hashlib.sha1((p + s)).hexdigest()
def algo_salt_sha1(p, s): return hashlib.sha1((s + p)).hexdigest()
def algo_sha256(p, s=None): return hashlib.sha256(p).hexdigest()
def algo_sha512(p, s=None): return hashlib.sha512(p).hexdigest()
def algo_ntlm(p, s=None): return hashlib.new('md4', p.decode('utf-8').encode('utf-16le')).hexdigest()
def algo_mysql(p, s=None): 
    s1 = hashlib.sha1(p).digest()
    return hashlib.sha1(s1).hexdigest()
def algo_ripemd160(p, s=None): return hashlib.new('ripemd160', p).hexdigest()
def algo_whirlpool(p, s=None): return hashlib.new('whirlpool', p).hexdigest()
def algo_hmac_md5(p, s): return hmac.new(p, s, hashlib.md5).hexdigest()
def algo_hmac_sha1(p, s): return hmac.new(p, s, hashlib.sha1).hexdigest()
def algo_hmac_sha256(p, s): return hmac.new(p, s, hashlib.sha256).hexdigest()
def algo_hmac_sha512(p, s): return hmac.new(p, s, hashlib.sha512).hexdigest()
def algo_bcrypt(p, s):
    if not HAS_BCRYPT: return None
    try:
        if bcrypt.checkpw(p, s): return s.decode('utf-8')
    except: pass
    return None
def algo_crypt_generic(p, s):
    if not HAS_CRYPT: return None
    try:
        hash_str = s.decode('utf-8')
        c = crypt.crypt(p.decode('utf-8'), hash_str)
        if c == hash_str: return hash_str
    except: pass
    return None
def algo_winzip(p, s):
    try:
        hash_str = s.decode('utf-8')
        parts = hash_str.split('*')
        if len(parts) < 8 or '$zip2$' not in parts[0]: return None
        algo_type = int(parts[1])
        bit_mode = int(parts[2])
        if algo_type != 1: return None
        salt = binascii.unhexlify(parts[5])
        verify = binascii.unhexlify(parts[7])
        key_len = {1: 16, 2: 24, 3: 32}.get(bit_mode)
        if not key_len: return None
        dk = hashlib.pbkdf2_hmac('sha1', p, salt, 1000, (2 * key_len) + 2)
        if dk[-2:] == verify: return hash_str
    except: pass
    return None

# --- MODE MAPPING ---
HASH_MODES = {
    0:    ("MD5", algo_md5, False),
    10:   ("MD5($pass.$salt)", algo_md5_salt, True),
    20:   ("MD5($salt.$pass)", algo_salt_md5, True),
    50:   ("HMAC-MD5 (key=$pass)", algo_hmac_md5, True),
    100:  ("SHA1", algo_sha1, False),
    110:  ("SHA1($pass.$salt)", algo_sha1_salt, True),
    120:  ("SHA1($salt.$pass)", algo_salt_sha1, True),
    150:  ("HMAC-SHA1 (key=$pass)", algo_hmac_sha1, True),
    1400: ("SHA2-256", algo_sha256, False),
    1450: ("HMAC-SHA256 (key=$pass)", algo_hmac_sha256, True),
    1700: ("SHA2-512", algo_sha512, False),
    1750: ("HMAC-SHA512 (key=$pass)", algo_hmac_sha512, True),
    500:  ("md5crypt ($1$)", algo_crypt_generic, True),
    1800: ("sha512crypt ($6$)", algo_crypt_generic, True),
    1000: ("NTLM", algo_ntlm, False),
    300:  ("MySQL", algo_mysql, False),
    2600: ("MD5(MD5($pass))", algo_md5_double, False),
    3200: ("Bcrypt", algo_bcrypt, True),
    6000: ("RIPEMD-160", algo_ripemd160, False),
    6100: ("Whirlpool", algo_whirlpool, False),
    13600:("WinZip (AES)", algo_winzip, True),
}

# --- WORKER FUNCTIONS ---

def attack_worker(chunk, target_hash, target_salt, mode_id):
    """Worker function for all attack modes"""
    algo_func = HASH_MODES[mode_id][1]
    requires_salt = HASH_MODES[mode_id][2]
    salt_bytes = target_salt.encode('utf-8') if target_salt else b''
    
    for password in chunk:
        if not password:
            continue
        
        try:
            password_bytes = password.encode('utf-8')
            
            if requires_salt:
                digest = algo_func(password_bytes, salt_bytes)
            else:
                digest = algo_func(password_bytes)
            
            if digest == target_hash or (digest and digest == target_salt):
                return password
        except Exception:
            continue
    return None

# --- HELPERS ---

def auto_detect_mode(hash_str):
    """Auto-detect hash type from string"""
    if hash_str.startswith("$2") and len(hash_str) > 50: 
        return 3200, hash_str, hash_str
    if hash_str.startswith("$zip2$"): 
        return 13600, hash_str, hash_str
    if hash_str.startswith("$1$"): 
        return 500, hash_str, hash_str
    if hash_str.startswith("$6$"): 
        return 1800, hash_str, hash_str
    if ':' in hash_str:
        h, s = hash_str.split(':', 1)
        if len(h) == 32: return 10, h, s
        if len(h) == 40: return 110, h, s
    
    l = len(hash_str)
    if l == 32: return 0, hash_str, None
    if l == 40: return 100, hash_str, None
    if l == 64: return 1400, hash_str, None
    if l == 128: return 1700, hash_str, None
    
    return None, hash_str, None

def count_combinations(attack_mode, **kwargs):
    """Calculate total combinations for progress bar"""
    if attack_mode == AttackModes.STRAIGHT:
        return count_lines(kwargs.get('wordlist', ''))
    
    elif attack_mode == AttackModes.MASK:
        mask = kwargs.get('mask', '')
        total = 1
        i = 0
        while i < len(mask):
            if i + 1 < len(mask) and mask[i] == '?' and mask[i+1] in CHAR_SETS:
                total *= len(CHAR_SETS[mask[i:i+2]])
                i += 2
            else:
                total *= 1
                i += 1
        return total
    
    elif attack_mode == AttackModes.COMBINATION:
        return count_lines(kwargs.get('wordlist1', '')) * count_lines(kwargs.get('wordlist2', ''))
    
    elif attack_mode in [AttackModes.HYBRID_WORDLIST_MASK, AttackModes.HYBRID_MASK_WORDLIST]:
        wordlist_count = count_lines(kwargs.get('wordlist', ''))
        mask_count = count_combinations(AttackModes.MASK, mask=kwargs.get('mask', ''))
        return wordlist_count * mask_count
    
    return 0

def count_lines(filepath):
    """Count lines in a file"""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return sum(1 for _ in f)
    except:
        return 0

def get_password_generator(attack_mode, **kwargs):
    """Get password generator based on attack mode"""
    if attack_mode == AttackModes.STRAIGHT:
        wordlist = kwargs.get('wordlist')
        with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                yield line.strip()
    
    elif attack_mode == AttackModes.MASK:
        mask = kwargs.get('mask')
        yield from mask_generator(mask)
    
    elif attack_mode == AttackModes.COMBINATION:
        yield from combination_generator(kwargs.get('wordlist1'), kwargs.get('wordlist2'))
    
    elif attack_mode == AttackModes.HYBRID_WORDLIST_MASK:
        yield from hybrid_generator(kwargs.get('wordlist'), kwargs.get('mask'), prepend=False)
    
    elif attack_mode == AttackModes.HYBRID_MASK_WORDLIST:
        yield from hybrid_generator(kwargs.get('wordlist'), kwargs.get('mask'), prepend=True)

def generate_chunks(generator, chunk_size=1000):
    """Split generator into chunks for multiprocessing"""
    chunk = []
    for item in generator:
        chunk.append(item)
        if len(chunk) >= chunk_size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk

# --- MAIN EXECUTION ---

def main():
    print_banner()
    
    # Warnings for missing modules
    if not HAS_BCRYPT:
        print(f"{Colors.WARNING}[!] 'bcrypt' module missing. Mode 3200 disabled.{Colors.ENDC}")
    if not HAS_CRYPT and os.name != 'nt':
        print(f"{Colors.WARNING}[!] 'crypt' module missing. Modes 500/1800 disabled.{Colors.ENDC}")
    elif os.name == 'nt':
        print(f"{Colors.WARNING}[!] Windows detected. Modes 500/1800 (Unix Crypt) disabled.{Colors.ENDC}")
    
    # Enhanced Argument Parser
    parser = argparse.ArgumentParser(
        description=f"{Colors.CYAN}PASSWORD CRACKER  v2.0 - Advanced Password Recovery Tool{Colors.ENDC}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Colors.GREEN}EXAMPLES:{Colors.ENDC}
  Dictionary Attack:
    python3 password.py -m 0 -d rockyou.txt '5d41402abc4b2a76b9719d911017c592'
  
  Mask Attack (4 lowercase + 2 digits):
    python3 password.py -m 0 -a 3 --mask "?l?l?l?l?d?d" '5d41402abc4b2a76b9719d911017c592'
  
  Combination Attack (two wordlists):
    python3 password.py -m 0 -a 1 -d words1.txt --wordlist2 words2.txt hash:salt
  
  Hybrid Attack (wordlist + mask):
    python3 password.py -m 0 -a 6 -d words.txt --mask "?d?d?s" hash
  
  Auto-detect hash type:
    python3 password.py -d rockyou.txt '5d41402abc4b2a76b9719d911017c592'
  
{Colors.YELLOW}MASK PLACEHOLDERS:{Colors.ENDC}
  ?l = lowercase letters (a-z)
  ?u = uppercase letters (A-Z)
  ?d = digits (0-9)
  ?s = special characters (!@#$%^&*)
  ?a = all printable characters
  ?h = lowercase hex (0-9, a-f)
  ?H = uppercase hex (0-9, A-F)
  ?n = alphanumeric (a-z, A-Z, 0-9)

{Colors.PURPLE}SUPPORTED HASH TYPES (use -m/--mode):{Colors.ENDC}
  0    MD5                        1400   SHA2-256
  10   MD5($pass.$salt)           1450   HMAC-SHA256
  20   MD5($salt.$pass)           1700   SHA2-512
  50   HMAC-MD5                   1750   HMAC-SHA512
  100  SHA1                       500    md5crypt ($1$)
  110  SHA1($pass.$salt)          1800   sha512crypt ($6$)
  120  SHA1($salt.$pass)          1000   NTLM
  150  HMAC-SHA1                  300    MySQL
  2600 MD5(MD5($pass))            3200   Bcrypt
  6000 RIPEMD-160                 6100   Whirlpool
  13600 WinZip (AES)
        """
    )
    
    # Required arguments
    parser.add_argument("hash", nargs='?', help="Target hash to crack")
    
    # Hash type arguments
    parser.add_argument("-m", "--mode", type=int, help="Hash type ID (use --list to see all)")
    
    # Attack mode arguments
    parser.add_argument("-a", "--attack-mode", type=int, default=0, 
                       choices=[0, 1, 3, 6, 7],
                       help="Attack mode: 0=Straight, 1=Combination, 3=Mask, 6=Hybrid Wordlist+Mask, 7=Hybrid Mask+Wordlist")
    
    # Wordlist arguments
    parser.add_argument("-d", "--wordlist", help="Path to primary wordlist")
    parser.add_argument("--wordlist2", help="Path to secondary wordlist (for combination attack)")
    
    # Mask arguments
    parser.add_argument("--mask", help="Mask pattern (e.g., ?l?l?l?d?d?d)")
    
    # Performance arguments
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS, 
                       help=f"Number of CPU cores to use (default: {DEFAULT_THREADS})")
    parser.add_argument("--chunk-size", type=int, default=1000, 
                       help="Chunk size for multiprocessing (default: 1000)")
    
    # Information arguments
    parser.add_argument("--list", action="store_true", help="List all supported hash types")
    parser.add_argument("--info", action="store_true", help="Show tool information and examples")
    parser.add_argument("--version", action="version", version="HashCracker v2.0")
    
    args = parser.parse_args()
    
    # Show information if requested
    if args.info:
        print(f"{Colors.CYAN}{'═'*70}")
        print("HASHCRACKER v2.0 - COMPANY PROJECT")
        print("Advanced Password Recovery Tool with Multiple Attack Modes")
        print(f"{'═'*70}{Colors.ENDC}")
        print("\nFeatures:")
        print("  ✓ Dictionary Attack (Straight)")
        print("  ✓ Mask Attack (Pattern-based brute force)")
        print("  ✓ Combination Attack (Two wordlists)")
        print("  ✓ Hybrid Attack (Wordlist + Mask)")
        print("  ✓ Salt Support (Hash:Salt format)")
        print("  ✓ Multi-threading (Parallel processing)")
        print("  ✓ Auto-detection of hash types")
        print("  ✓ Progress bar with statistics")
        print("  ✓ Support for 20+ hash algorithms")
        sys.exit(0)
    
    # List hash types if requested
    if args.list:
        print(f"{Colors.HEADER}╔{'═'*45}╗")
        print(f"║{'SUPPORTED HASH TYPES':^45}║")
        print(f"╚{'═'*45}╝{Colors.ENDC}")
        print(f"{'ID':<6} {'Name':<30} {'Salted?':<8}")
        print(f"{'─'*6} {'─'*30} {'─'*8}")
        for mid, (name, _, salted) in sorted(HASH_MODES.items()):
            print(f"{mid:<6} {name:<30} {str(salted):<8}")
        sys.exit(0)
    
    # Validate attack mode requirements
    if args.attack_mode == AttackModes.COMBINATION and not args.wordlist2:
        print(f"{Colors.FAIL}[!] Combination attack requires --wordlist2{Colors.ENDC}")
        sys.exit(1)
    
    if args.attack_mode in [AttackModes.MASK, AttackModes.HYBRID_WORDLIST_MASK, 
                           AttackModes.HYBRID_MASK_WORDLIST] and not args.mask:
        print(f"{Colors.FAIL}[!] Mask/Hybrid attack requires --mask{Colors.ENDC}")
        sys.exit(1)
    
    # Get target hash
    target_input = args.hash
    if not target_input:
        target_input = input(f"{Colors.BOLD}Enter Hash (or hash:salt): {Colors.ENDC}").strip()
    
    # Auto-detect mode if not specified
    detected_mode, clean_hash, extracted_salt = auto_detect_mode(target_input)
    mode = args.mode if args.mode is not None else detected_mode
    
    if mode is None:
        print(f"{Colors.FAIL}[!] Could not auto-detect hash type. Use -m to specify.{Colors.ENDC}")
        sys.exit(1)
    
    if mode not in HASH_MODES:
        print(f"{Colors.FAIL}[!] Unsupported hash mode: {mode}{Colors.ENDC}")
        sys.exit(1)
    
    # Special handling for modular hashes
    if mode in [500, 1800, 3200, 13600] and args.mode is not None:
        clean_hash = target_input
        extracted_salt = target_input
    
    algo_name = HASH_MODES[mode][0]
    
    # Get wordlist if needed
    wordlist = args.wordlist
    if args.attack_mode in [AttackModes.STRAIGHT, AttackModes.COMBINATION, 
                           AttackModes.HYBRID_WORDLIST_MASK, AttackModes.HYBRID_MASK_WORDLIST]:
        if not wordlist:
            print(f"\n{Colors.CYAN}[?] Wordlist required for this attack mode.{Colors.ENDC}")
            while True:
                wordlist = input(f"Enter path to wordlist: ").strip().replace('"', '')
                if os.path.isfile(wordlist):
                    break
                print(f"{Colors.FAIL}[!] File not found.{Colors.ENDC}")
    
    # Display configuration
    print(f"\n{Colors.HEADER}{'═'*60}")
    print("ATTACK CONFIGURATION")
    print(f"{'═'*60}{Colors.ENDC}")
    
    print_info("Attack Mode", AttackModes.get_mode_name(args.attack_mode))
    print_info("Hash Type", f"{mode} ({algo_name})")
    print_info("Target Hash", f"{clean_hash[:20]}..." if len(clean_hash) > 20 else clean_hash)
    
    if extracted_salt:
        salt_display = extracted_salt[:20] + "..." if len(extracted_salt) > 20 else extracted_salt
        print_info("Salt", salt_display)
    
    if args.attack_mode in [AttackModes.MASK, AttackModes.HYBRID_WORDLIST_MASK, 
                           AttackModes.HYBRID_MASK_WORDLIST]:
        print_info("Mask Pattern", args.mask)
    
    if wordlist:
        print_info("Wordlist", wordlist)
    
    if args.wordlist2:
        print_info("Wordlist 2", args.wordlist2)
    
    print_info("Threads", args.threads)
    print_info("Start Time", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
    # Calculate total combinations
    total_combinations = count_combinations(
        args.attack_mode, 
        wordlist=wordlist,
        wordlist1=wordlist,
        wordlist2=args.wordlist2,
        mask=args.mask
    )
    
    if total_combinations > 0:
        print_info("Total Combinations", f"{total_combinations:,}")
    
    print(f"{Colors.HEADER}{'═'*60}{Colors.ENDC}\n")
    
    # Prepare attack parameters
    attack_params = {
        'wordlist': wordlist,
        'wordlist1': wordlist,
        'wordlist2': args.wordlist2,
        'mask': args.mask
    }
    
    # Create password generator
    try:
        password_gen = get_password_generator(args.attack_mode, **attack_params)
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error creating password generator: {e}{Colors.ENDC}")
        sys.exit(1)
    
    # Start attack
    start_time = time.time()
    found_password = None
    attempts = 0
    
    print(f"{Colors.YELLOW}[+] Starting attack...{Colors.ENDC}\n")
    
    # Configure chunk size based on hash type
    chunk_size = 500 if mode in [3200, 13600] else args.chunk_size
    
    # Create worker function
    worker = functools.partial(
        attack_worker, 
        target_hash=clean_hash, 
        target_salt=extracted_salt, 
        mode_id=mode
    )
    
    # Create pool and process chunks
    pool = multiprocessing.Pool(processes=args.threads)
    
    try:
        # Process in chunks with progress bar
        for chunk_num, chunk in enumerate(generate_chunks(password_gen, chunk_size)):
            attempts += len(chunk)
            
            # Update progress every 10 chunks
            if chunk_num % 10 == 0:
                speed = attempts / (time.time() - start_time) if time.time() > start_time else 0
                print(f"\r{Colors.BLUE}[*] Progress: {attempts:,} attempts | Speed: {speed:,.0f} hashes/sec{Colors.ENDC}", end="")
            
            result = worker(chunk)
            if result:
                found_password = result
                pool.terminate()
                break
        
        pool.close()
        
    except KeyboardInterrupt:
        pool.terminate()
        print(f"\n\n{Colors.WARNING}[!] Attack interrupted by user.{Colors.ENDC}")
        sys.exit(0)
    except Exception as e:
        pool.terminate()
        print(f"\n\n{Colors.FAIL}[!] Error during attack: {e}{Colors.ENDC}")
        sys.exit(1)
    
    finally:
        pool.join()
    
    end_time = time.time()
    time_taken = end_time - start_time
    
    # Display results
    if found_password:
        print_success(
            found_password, 
            mode=AttackModes.get_mode_name(args.attack_mode),
            time_taken=time_taken,
            attempts=attempts,
            salt=extracted_salt
        )
    else:
        print(f"\n{Colors.FAIL}{'═'*60}")
        print("ATTACK FAILED")
        print(f"{'═'*60}{Colors.ENDC}")
        print(f"\n{Colors.WARNING}[!] Password not found in the search space.{Colors.ENDC}")
        print_stats(start_time, end_time, attempts, attempts/time_taken if time_taken > 0 else 0)
        print(f"\n{Colors.CYAN}Suggestions:{Colors.ENDC}")
        print("  1. Try a larger wordlist")
        print("  2. Use a different attack mode")
        print("  3. Verify the hash format")
        print("  4. Check if salt is needed\n")

if __name__ == '__main__':
    main()

