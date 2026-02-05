# HashCracker 

**HashCracker** is an advanced, multi-threaded password recovery tool written in Python. It is designed to be fast, efficient, and versatile, supporting multiple attack modes (Dictionary, Mask, Hybrid) and over 20 different hashing algorithms including MD5, SHA-series, NTLM, MySQL, and specialized formats like WinZip and Bcrypt.



---

## Features

* **Multi-Core Processing:** Utilizes Python's `multiprocessing` to maximize CPU usage.
* **Auto-Detection:** Automatically identifies common hash types (MD5, SHA1, SHA256, etc.).
* **5 Attack Modes:**
    * **Straight (Dictionary):** Standard wordlist attack.
    * **Combination:** Combines words from two different wordlists.
    * **Mask:** Brute-force using specific patterns (e.g., 4 lowercase letters + 2 digits).
    * **Hybrid:** Combines Wordlists with Masks (append or prepend).
* **Salt Support:** robust support for salted hashes in `hash:salt` format.
* **Live Statistics:** Real-time progress bar showing speed (hashes/sec) and estimated completion.

---

##  Requirements

* **Python 3.x**
* **OS:** Linux 
* **Optional Modules:**
    * `bcrypt` (for Bcrypt support)

### Installation

```bash
# Clone the repository
git clone https://github.com/ajayyanshu/HashCracker.git
cd HashCracker

# Execution
chomd *+ password.py

# (Optional) Install bcrypt for Mode 3200 support
pip3 install bcrypt

```
## Usage
Basic Syntax
```bash
python3 password.py [HASH] [OPTIONS]

```

## Command Line Arguments

| Argument | Description |
| :--- | :--- |
| **Positional** | |
| `hash` | The target hash or `hash:salt` string. |
| **Configuration** | |
| `-m`, `--mode` | The Hash Type ID (see list below). Auto-detected if omitted. |
| `-a`, `--attack-mode` | Attack mode: `0` (Dict), `1` (Combo), `3` (Mask), `6/7` (Hybrid). |
| `-t`, `--threads` | Number of CPU threads to use (Default: 4). |
| **Input Sources** | |
| `-d`, `--wordlist` | Path to the primary wordlist (Required for Modes 0, 1, 6, 7). |
| `--wordlist2` | Path to secondary wordlist (Required for Mode 1). |
| `--mask` | Pattern mask (Required for Modes 3, 6, 7). |
| **Info** | |
| `--list` | List all supported hash types and IDs. |
| `--info` | Show detailed tool information. |

##  Attack Modes

### 1. Dictionary Attack
   Reads passwords line-by-line from a wordlist.

```bash
python3 password.py -m 0 -d rockyou.txt '5d41402abc4b2a76b9719d911017c592'

```
### 2. Mask Attack (`-a 3`)
Brute-forces based on a specific character pattern.

**Mask Placeholders:**
* `?l` = Lowercase (a-z)
* `?u` = Uppercase (A-Z)
* `?d` = Digits (0-9)
* `?s` = Special (!@#$...)
* `?a` = All printable
* `?h` / `?H` = Hex (lower/upper)

**Example:** Crack a password known to be 4 lowercase letters followed by 2 digits (e.g., "pass12"):
```bash
python3 password.py -m 0 -a 3 --mask "?l?l?l?l?d?d" <hash>

```
## 3. **Combination Attack (-a 1)**
Combines words from two files (e.g., names.txt + dates.txt).
```bash
python3 password.py -m 0 -a 1 -d words1.txt --wordlist2 words2.txt hash:salt

```
## 4. Hybrid Attack (-a 6 or -a 7)

* Mode 6 (Wordlist + Mask): Appends mask to word (e.g., Password + 123).
* Mode 7 (Mask + Wordlist): Prepends mask to word (e.g., 123 + Password).

```bash
# Appends 3 digits to every word in rockyou.txt
python3 password.py -m 0 -a 6 -d words.txt --mask "?d?d?s" hash

```
##  Supported Hash Types (Common)

Use `--list` to see the full table of 20+ algorithms.

| ID | Algorithm | Example Format |
| :--- | :--- | :--- |
| **0** | MD5 | `5d4140...` |
| **10** | MD5(Pass.Salt) | `hash:salt` |
| **100** | SHA1 | `a9993e...` |
| **1000** | NTLM | `b4b9b0...` |
| **1400** | SHA2-256 | `ef797c...` |
| **3200** | Bcrypt | `$2a$10$...` |
| **13600** | WinZip (AES) | `$zip2$*...` |

###  Support & Donations
If you find HashCracker useful and would like to support its development, please consider making a donation and would like to support its development, please consider making a donation. Your contributions help us maintain and improve the project.

[![Donate](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEjd9o3K2CK9LObsNOok8nY4WYMSwKkhAzsz7NDxmO8eZU-d8dw4kEKW1Ycp3QpzVsT2okmWwoBXLXB757yQhoL0Xandlt3Wjwdw7tTlU4hTGdJcFH1tq1i0K6o7uTTGK-20fKi7DQhgoYEZkHI1-Y9UPBWAjiNhtn8TceqHS4O6kTaaeNweZe6OBJ0Ve0ou/s424/download.png)](https://buymeacoffee.com/ajayyanshu)

[![Donate](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEgMgW12teTME3e1Ap4Lc6MuQ7mFoEfyKINWAQ8dDx0vRR6XXNXGNXSaOgFdFhB2kTv8d6r5TiMIpRqJv9EnrM2YU1Syrvq4KO32YcmjiJk-GLuxHGMwfTPIO1Zz1JE2lCSMTRcrY1JJues1jpC4qotBNumo3d3dC79uRFulGasM8vzSdneJmzunxKDiUKI2/s386/upi.PNG)]()


##  Contact

**Ajay Kumar** *Security Engineer & Developer* [![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=flat&logo=linkedin)](https://linkedin.com/in/ajayyanshu/) [![GitHub](https://img.shields.io/badge/GitHub-Follow-black?style=flat&logo=github)](https://github.com/ajayyanshu) [![Instagram](https://img.shields.io/badge/Instagram-Follow-black?style=flat&logo=instagram)](https://www.instagram.com/ajayyanshu/)
   Feedback or issues? Reach out at ajayyanshu@gmail.com
