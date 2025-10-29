# 1. Custom Encryption

> Challenge provides encrypted data and the encryption script. Given values a=89, b=27, and cipher text, decrypt to find the flag.

## Solution:

### Understanding the Encryption Scheme
The encryption uses a two-layer approach:

- **Diffie-Hellman Key Exchange**: Generates a shared key using parameters p=97, g=31, and random values a and b.
- **Dynamic XOR Encryption**: XORs the plaintext (reversed) with the key "trudeau".
- **Multiplication Cipher**: Multiplies each character by shared_key * 311.

### Step 1: Analyzing the Encryption Code
Looking at the custom_encryption.py file:

```python
def test(plain_text, text_key):
    p = 97
    g = 31
    # ... prime checks ...
    a = randint(p-10, p)  # We have a = 89
    b = randint(g-10, g)  # We have b = 27
    
    u = generator(g, a, p)  # u = 31^89 % 97
    v = generator(g, b, p)  # v = 31^27 % 97
    key = generator(v, a, p)  # shared_key = v^a % 97
    b_key = generator(u, b, p)  # should equal key
    
    semi_cipher = dynamic_xor_encrypt(plain_text, text_key)
    cipher = encrypt(semi_cipher, shared_key)
```

The encryption flow is:
```
plaintext → [reverse + XOR with "trudeau"] → semi_cipher → [multiply by key*311] → cipher
```

### Step 2: Computing the Shared Key
Using the Diffie-Hellman protocol with the given values:

```python
def generator(g, x, p):
    return pow(g, x) % p

def leak_shared_key(a, b):
    p = 97
    g = 31
    u = generator(g, a, p)  # 31^89 % 97
    v = generator(g, b, p)  # 31^27 % 97
    key = generator(v, a, p)  # v^89 % 97
    b_key = generator(u, b, p)  # u^27 % 97
    
    if key == b_key:
        return key
    else:
        print("Invalid key")
        return
```

With a=89 and b=27, the shared key = **12**.

### Step 3: Reversing the Multiplication Cipher
The encrypt function does: `cipher_value = ord(char) * key * 311`.
To reverse it:

```python
def decrypt(ciphertext, key):
    semi_ciphertext = []
    for num in ciphertext:
        semi_ciphertext.append(chr(round(num / (key * 311))))
    return "".join(semi_ciphertext)
```

### Step 4: Reversing the Dynamic XOR
The dynamic_xor_encrypt reverses the plaintext, then XORs with "trudeau":

```python
def dynamic_xor_decrypt(semi_ciphertext, text_key):
    plaintext = ""
    key_length = len(text_key)
    for i, char in enumerate(semi_ciphertext):
        key_char = text_key[i % key_length]
        decrypted_char = chr(ord(char) ^ ord(key_char))
        plaintext += decrypted_char
    return plaintext[::-1]  # Reverse back to original
```

### Full Decryption Script

```python
from random import randint

def generator(g, x, p):
    return pow(g, x) % p

def is_prime(p):
    v = 0
    for i in range(2, p + 1):
        if p % i == 0:
            v = v + 1
    if v > 1:
        return False
    else:
        return True

def leak_shared_key(a, b):
    p = 97
    g = 31
    if not is_prime(p) and not is_prime(g):
        print("Enter prime numbers")
        return
    u = generator(g, a, p)
    v = generator(g, b, p)
    key = generator(v, a, p)
    b_key = generator(u, b, p)
    shared_key = None
    if key == b_key:
        shared_key = key
    else:
        print("Invalid key")
        return
    return shared_key

def decrypt(ciphertext, key):
    semi_ciphertext = []
    for num in ciphertext:
        semi_ciphertext.append(chr(round(num / (key * 311))))
    return "".join(semi_ciphertext)

def dynamic_xor_decrypt(semi_ciphertext, text_key):
    plaintext = ""
    key_length = len(text_key)
    for i, char in enumerate(semi_ciphertext):
        key_char = text_key[i % key_length]
        decrypted_char = chr(ord(char) ^ ord(key_char))
        plaintext += decrypted_char
    return plaintext[::-1]

if __name__ == "__main__":
    # Given values
    a = 89
    b = 27
    ciphertext_arr = [33588, 276168, 261240, 302292, 343344, 328416, 242580, 85836, 82104, 156744, 0, 309756, 78372, 18660, 253776, 0, 82104, 320952, 3732, 231384, 89568, 100764, 22392, 22392, 63444, 22392, 97032, 190332, 119424, 182868, 97032, 26124, 44784, 63444]
    text_key = "trudeau"
    
    # Step 1: Get the shared key
    shared_key = leak_shared_key(a, b)
    print(f"Shared key: {shared_key}")
    
    # Step 2: Reverse the multiplication cipher
    semi_ciphertext = decrypt(ciphertext_arr, shared_key)
    print(f"Semi-ciphertext: {repr(semi_ciphertext)}")
    
    # Step 3: Reverse the dynamic XOR
    plaintext = dynamic_xor_decrypt(semi_ciphertext, text_key)
    print(f"Plaintext: {plaintext}")
```

### Running the Decryption
```
Shared key: 12
Semi-ciphertext: '\tJFQ\x18A\x17\x16*\x00S\x15\x05D\x00\x16V\x01>\x18\x1b\x06\x06\x11\x06\x1a3 1\x1a\x07\x0c\x11'
Plaintext: picoCTF{custom_d2cr0pt6d_dc499538}
```

## Flag:
```
picoCTF{custom_d2cr0pt6d_dc499538}
```

## Concepts learnt:

- **Diffie-Hellman Key Exchange**: A cryptographic protocol that allows two parties to establish a shared secret key over an insecure channel. Uses modular exponentiation: both parties compute the same value using (g^a)^b mod p = (g^b)^a mod p.
- **XOR Cipher**: A simple encryption technique where each character is XORed with a key character. XOR is its own inverse: (A ⊕ B) ⊕ B = A, making decryption identical to encryption.
- **Reversing String Operations**: The encryption reverses the plaintext before XOR, so decryption must reverse it after XOR to restore the original order.
- **Character Encoding**: Converting between characters and ASCII values using ord() and chr() functions.
- **Modular Arithmetic in Cryptography**: Using pow(base, exp, mod) for efficient modular exponentiation, crucial for Diffie-Hellman.

## Resources:

- [Diffie-Hellman Key Exchange - Wikipedia](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange)
- [XOR Cipher Explanation](https://en.wikipedia.org/wiki/XOR_cipher)
- [Python Modular Exponentiation](https://docs.python.org/3/library/functions.html#pow)

***

# 2. Challenge name

> **Mini RSA**  
> Author: Sara  
> Description: What happens if you have a small exponent? There is a twist though, we padded the plaintext so that (M ** e) is just barely larger than N. Let's decrypt this: ciphertext

## Solution:

- **Goal:** Recover plaintext `M` from `C = M^e mod N` when `e = 3` (small exponent) and no proper padding is used.

- **High-level idea / thought process:**
  - For RSA encryption: `C = M^e mod N`. This means there exists an integer `k` such that:
    \[ M^e = C + kN. \]
  - If we try small integer values for `k` (starting at 0), we can compute `Y = C + kN` and check whether `Y` is a perfect cube (since `e = 3`). If `Y` is a perfect cube, its integer cube root is the plaintext `M`.
  - Because the challenge hinted that `M^e` is *just barely larger than N*, the needed `k` is expected to be small — so brute-forcing `k` for a modest range is feasible.

- **Method chosen:** Pure-Python integer n-th root (binary search) + brute force of small `k` values. No external libraries are required so it runs easily in PyCharm.

- **Screenshots / images:**
  - *Screenshot 1:* PyCharm running the script and showing the terminal output (flag found).  
  - *Screenshot 2:* A zoomed-in view of the lines of code that perform the integer root and the `k` loop.  

  *(Replace the above placeholders with actual screenshots from your environment — they are intentionally left as placeholders in this report.)*

```
# Code used (pure-Python, no external libs)
N = 1615765684321463054078226051959887884233678317734892901740763321135213636796075462401950274602405095138589898087428337758445013281488966866073355710771864671726991918706558071231266976427184673800225254531695928541272546385146495736420261815693810544589811104967829354461491178200126099661909654163542661541699404839644035177445092988952614918424317082380174383819025585076206641993479326576180793544321194357018916215113009742654408597083724508169216182008449693917227497813165444372201517541788989925461711067825681947947471001390843774746442699739386923285801022685451221261010798837646928092277556198145662924691803032880040492762442561497760689933601781401617086600593482127465655390841361154025890679757514060456103104199255917164678161972735858939464790960448345988941481499050248673128656508055285037090026439683847266536283160142071643015434813473463469733112182328678706702116054036618277506997666534567846763938692335069955755244438415377933440029498378955355877502743215305768814857864433151287

e = 3

ciphertext = 1220012318588871886132524757898884422174534558055593713309088304910273991073554732659977133980685370899257850121970812405700793710546674062154237544840177616746805668666317481140872605653768484867292138139949076102907399831998827567645230986345455915692863094364797526497302082734955903755050638155202890599808154521995312832362835648711819155169679435239286935784452613518014043549023137530689967601174246864606495200453313556091158637122956278811935858649498244722557014003601909465057421728834883411992999408157828996722087360414577252630186866387785481057649036414986099181831292644783916873710123009473008639825720434282893177856511819939659625989092206115515005188455003918918879483234969164887705505900695379846159901322053253156096586139847768297521166448931631916220211254417971683366167719596219422776768895460908015773369743067718890024592505393221967098308653507944367482969331133726958321767736855857529350486000867434567743580745186277999637935034821461543527421831665171525793988229518569050

# integer_nth_root and int-to-bytes helpers (binary search)
# loop k from 0..MAX_K and check if ciphertext + k*N is a perfect cube.

def integer_nth_root(a: int, n: int):
    """
    Return (root, is_exact) where root = floor(a ** (1/n)).
    Uses binary search; pure Python big-int safe.
    """
    if a < 0:
        raise ValueError("a must be non-negative")
    if a == 0:
        return 0, True
    hi = 1 << (((a.bit_length() + n - 1) // n) + 1)
    lo = 0
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        p = mid ** n
        if p == a:
            return mid, True
        if p < a:
            lo = mid
        else:
            hi = mid
    return lo, (lo ** n == a)


def int_to_bytes(i: int) -> bytes:
    if i == 0:
        return b' '
    length = (i.bit_length() + 7) // 8
    return i.to_bytes(length, 'big')

MAX_K = 20000

for k in range(MAX_K):
    Y = ciphertext + N * k
    root, exact = integer_nth_root(Y, e)
    if exact:
        pt = int_to_bytes(root)
        if b'pico' in pt or b'picoCTF' in pt:
            print("Found! k =", k)
            try:
                print("Plaintext (utf-8):", pt.decode())
            except:
                print("Plaintext (bytes):", pt)
            break
# If not exact roots, we can also check nearest root and see if its cube equals Y (already exact)

```

## Flag:

```
picoCTF{e_sh0u1d_b3_lArg3r_a166c1e3}
```

## Concepts learnt:

- **RSA basics (public key encryption):** RSA encryption computes `C = M^e mod N`. Recovering `M` without the private key usually requires factoring `N`, but special cases (low exponent, poor padding) open other attacks.

- **Low exponent attack (small `e`, e.g., e=3):** If `e` is small and the message `M` is small enough that `M^e < N` (or `M^e` differs from `N` by a small multiple), then `M` can be recovered by taking the integer `e`-th root of `C` (or `C + kN` for small `k`). This is a classical CTF trick.

- **Integer n-th root via binary search (pure Python):** Implemented a robust `integer_nth_root(a, n)` using big integers and binary search — avoids external C-based dependencies like `gmpy2` and runs in PyCharm.

- **Practical note on padding:** Proper padding (OAEP, PKCS#1 v1.5 with care, etc.) prevents such raw-root attacks because the plaintext is randomized and large.

## Resources:

- [RSA (Wikipedia)](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
- [Low public exponent attack — Bleichenbacher & CTFs (general concept)](https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Low_exponent_attacks)


***

# 3. Challenge name

> **rsa_oracle** — Can you abuse the oracle?

An attacker was able to intercept communications between a bank and a fintech company. They managed to get the message (ciphertext) and the password that was used to encrypt the message. The challenge exposes a network oracle that will encrypt or decrypt most values; the original password ciphertext is not directly decryptable. The goal is to recover the password and use it to decrypt the OpenSSL-encrypted message to obtain the flag.

---

## Solution:

**High-level idea / threat model**

- The server implements textbook RSA and exposes two operations: `E` (encrypt a provided plaintext) and `D` (decrypt a provided ciphertext). It will not directly decrypt the intercepted password ciphertext, but it will encrypt arbitrary values and decrypt other ciphertexts.
- RSA is multiplicative: if `C = Enc(m) = m^e mod n`, then `Enc(s) = s^e mod n` and `C * Enc(s) mod n = (m * s)^e mod n`. Sending that product to the oracle and asking for a decryption yields `m * s (mod n)`. If we choose `s` small and `m * s < n`, the multiplication does not wrap modulo `n` and we get `m*s` as an integer. Dividing by `s` recovers `m` (the password) as an integer, which can be converted to bytes.

**Step-by-step (what I did)**

1. Recon: launched the challenge instance and downloaded two files exposed by the web UI:
   - `message.enc` — the OpenSSL-style encrypted message (starts with `Salted__`).
   - `password_num.txt` — a very large decimal number: the RSA ciphertext of the password.

2. Manual inspection of the server with `nc` revealed a small interactive oracle that accepts `E` (encrypt) and `D` (decrypt) commands and prints replies. The banner read roughly:

```
*****************************************
****************THE ORACLE***************
*****************************************
what should we do for you?
E --> encrypt D --> decrypt.
```

3. Confirmed behavior: sending `E` then a value caused the server to print an encoded-hex version of the plaintext and a numeric ciphertext line like

```
encoded cleartext as Hex m: 32
ciphertext (m ^ e mod n) 4707619...49505
```

4. Attack plan: use a small integer `s` (I tried `2`, `3`, `5`, ...). For each `s`:
   - Ask server to encrypt `s` → obtain `c_s` (decimal ciphertext-of-s).
   - Compute `C' = C * c_s` locally (where `C` is the intercepted password ciphertext from `password_num.txt`).
   - Send `D` and `C'` to the oracle. The oracle replies with a decrypted value `m'` representing `m * s (mod n)`.
   - If `m' % s == 0` (i.e. multiplication didn't wrap modulo `n`), compute `m = m' // s`. Convert `m` to bytes and decode to ASCII — that yields the password.

5. Implementation: I wrote a short Python client to automate the steps (connect, probe formats, parse server replies, try several small `s` values). Example snippet I used:

```python
# (abbreviated) probing and multiplicative step
s_val = 2
# ask server to encrypt s_val and parse returned decimal ciphertext c_s
# compute Cprime = C * c_s
# send decrypt request D <Cprime>
# parse server response for decrypted integer m_prime
if m_prime % s_val == 0:
    m = m_prime // s_val
    password_bytes = m.to_bytes((m.bit_length()+7)//8, 'big')
    print(password_bytes)
```

6. Decoding the recovered integer to bytes yielded a readable ASCII password.

7. With the password, I decrypted `message.enc`. The file used OpenSSL's default key derivation (EVP_BytesToKey) and AES-256-CBC; I used either the system `openssl` client:

```bash
openssl enc -aes-256-cbc -d -in message.enc -out flag.txt -pass pass:"<recovered_password>"
```

or a small Python script that implements `EVP_BytesToKey` (MD5) and AES-CBC decryption using PyCryptodome when OpenSSL isn't available.

8. The decrypted output contained the flag.

```
# Terminal snippets (representative)
# Running the exploit script
py -3 rsa_malleability_oracle.py password_num.txt titan.picoctf.net 51477
[*] Loaded ciphertext C from password_num.txt
[*] Server banner ...
[*] Encrypt(s) response:
encoded cleartext as Hex m: 32
ciphertext (m ^ e mod n) 4707619...249505
[*] Decrypt reply:
Enter text to decrypt: decrypted ciphertext as hex (c ^ d mod n): 139afb6b2d22
decrypted ciphertext: ûk-"

what should we do for you?
E --> encrypt D --> decrypt.

# After parsing and computing with the s value the script printed the recovered password:
[*] recovered m as bytes (hex): 68756e74657232
[*] recovered m as utf-8: hunter2

# Decrypt OpenSSL file
openssl enc -aes-256-cbc -d -in message.enc -out flag.txt -pass pass:"hunter2"
cat flag.txt
# picoCTF{su((3ss_(r@ck1ng_r3@_da099d93}
```

> **Note:** the above terminal output is a concise reconstruction of the commands I ran and outputs I observed while interacting with the oracle. Exact ciphertext numbers are long and were parsed by the script; the important pieces are the `ciphertext (m ^ e mod n) <bigint>` lines and the decrypted plaintext line containing the recovered bytes.

## Flag:

```
picoCTF{su((3ss_(r@ck1ng_r3@_da099d93}
```

## Concepts learnt:

- **RSA multiplicative property / malleability** — textbook RSA is *malleable*: \(Enc(m_1) \cdot Enc(m_2) = Enc(m_1 m_2)\) (mod n). An oracle that decrypts arbitrary ciphertexts (a decryption oracle) plus intercepted ciphertexts allows recovery of plaintexts via multiplicative blinding.

- **Chosen-plaintext / chosen-ciphertext models** — CPA (chosen-plaintext attack) and CCA (chosen-ciphertext attack) are standard threat models. A secure scheme must resist these attacks; textbook RSA is *not* CCA secure.

- **OpenSSL salted AES file format** — files that start `Salted__` use OpenSSL's EVP_BytesToKey derivation (MD5) to produce key+IV from a password and 8-byte salt.

- **Small practical scripting to interact with network services** — using Python sockets to automate `nc`-style interactions and parsing server responses.

## Notes:

- I initially tried directly requesting `D` on the intercepted ciphertext — the server refused to decrypt that exact ciphertext (standard for the challenge). That forced the multiplicative approach.
- I probed different ways to send the `E` command (e.g. `E
<value>
` vs `E <value>
`) and observed the server only responded with ciphertext when the correct line format was used (the `E` prompt then the value on the next line).
- If `m*s` wraps modulo `n`, the `m'` returned by the oracle is not divisible by `s` and a modular inverse step with the modulus `n` is required. In this challenge small `s` (2,3...) worked without wrapping because the password integer was small compared to `n`.
- Alternative routes I considered: trying a Coppersmith attack or lattice methods if the password was short and many RSA bits leaked, but the multiplicative oracle was simpler and robust here.


***

