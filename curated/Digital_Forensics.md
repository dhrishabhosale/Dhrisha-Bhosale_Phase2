# Digital Forensics


---

# Hide and Seek

> A stego + forensics challenge: recover the hidden flag inside an image.

---

## Description

We were given an image that contained a hidden message. The goal was to locate and extract the hidden file (the flag) using forensic and steganography tools. The challenge hint suggested using `stegseek` for a `steghide` embed.

---

## Tools used

- **AperiSolve** — online stego/forensics analyzer (initial automated scan).
- **7z** — to extract the AperiSolve output archive.
- **Foremost** — file carving / recovery from raw blobs.
- **Steghide** — detect & extract steganographic payloads.
- **Stegseek** — automated passphrase bruteforce for `steghide` payloads.
- **rockyou.txt** — password wordlist used by stegseek.

---

## Step-by-step solution

### 1. Initial automated analysis
Upload the supplied image to AperiSolve. AperiSolve runs a battery of tools and produced a `.7z` archive containing `audit.txt` and carved files. The important carved file was `jpg/00000000.jpg` (a carved JPEG).

### 2. Extract AperiSolve output locally
```bash
cp "/mnt/c/Users/Dhrisha Bhosale/Downloads/foremost.7z" ~/
mkdir -p ~/foremost_extracted
7z x ~/foremost.7z -o~/foremost_extracted
```

A quick listing/inspection showed `audit.txt` and `jpg/00000000.jpg`.

### 3. Inspect the Foremost audit
```bash
cat ~/foremost_extracted/audit.txt | head -n 50
```
This confirmed Foremost carved a single JPG (`00000000.jpg`) from the uploaded blob.

### 4. Prepare a working directory and copy the carved image
```bash
mkdir -p ~/steg_work
cp ~/foremost_extracted/jpg/00000000.jpg ~/steg_work/00000000.jpg
ls -lah ~/steg_work
```

### 5. Check the carved image for steghide payload
```bash
steghide info ~/steg_work/00000000.jpg
```
`steghide` reported capacity and when asked to get embedded data it required a passphrase (indicating encrypted steghide payload present).

### 6. Obtain a wordlist (rockyou) and run stegseek
Download a usable rockyou wordlist (SecLists path varies; a common mirror or subset can be used):
```bash
sudo mkdir -p /usr/share/wordlists
sudo wget -O /usr/share/wordlists/rockyou.txt "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou-75.txt"
```
Run stegseek:
```bash
stegseek ~/steg_work/00000000.jpg /usr/share/wordlists/rockyou.txt
```
Observed output:
```
[i] Found passphrase: "iloveyou1"
[i] Original filename: "flag.txt".
[i] Extracting to "00000000.jpg.out".
```

### 7. Locate and read the extracted file
```bash
find ~ -type f -name "00000000.jpg.out"
cat /root/00000000.jpg.out
```
Output (flag):
```
nite{h1d3_4nd_s33k_but_w1th_st3g_sdfu9s8}
```

---

## Final Flag
```
nite{h1d3_4nd_s33k_but_w1th_st3g_sdfu9s8}
```

---

## Concepts learned

- **File carving (Foremost):** scanning raw data for known file headers and footers to recover embedded files.
- **Steganography (Steghide):** embedding data into images/audio; detection and extraction require the correct passphrase when encrypted.
- **Automated cracking (Stegseek):** feeding a wordlist to test many candidate passphrases until `steghide` accepts one and extracts the payload.
- **Wordlist management:** rockyou (or curated subsets) are standard in CTFs for guessing likely passphrases.

---

## Notes & troubleshooting

- AperiSolve produced the carved archive; Foremost’s `audit.txt` was the authoritative source that told us which carved file to analyze.
- Watch out for weird archive paths — AperiSolve sometimes outputs paths with literal `~` segments; copy carved files into a clean working folder to avoid confusion.
- If stegseek fails, alternatives include manual targeted guesses, trying other wordlists or running other stego tools (zsteg, stegsolve, binwalk, strings, exiftool) depending on file type.

---

## Reproducible command block

```bash
# extract AperiSolve output
7z x ~/foremost.7z -o~/foremost_extracted

# copy carved image
mkdir -p ~/steg_work
cp ~/foremost_extracted/jpg/00000000.jpg ~/steg_work/00000000.jpg

# check steghide
steghide info ~/steg_work/00000000.jpg

# download rockyou
sudo mkdir -p /usr/share/wordlists
sudo wget -O /usr/share/wordlists/rockyou.txt "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou-75.txt"

# run stegseek
stegseek ~/steg_work/00000000.jpg /usr/share/wordlists/rockyou.txt

# read extracted file
cat /root/00000000.jpg.out
```

---

## References

- AperiSolve — https://www.aperisolve.com
- Foremost manual — https://linux.die.net/man/1/foremost
- Steghide manual — https://linux.die.net/man/1/steghide
- Stegseek GitHub — https://github.com/RickdeJager/StegSeek
- SecLists — https://github.com/danielmiessler/SecLists

---

*End of writeup.*


---

# 🧩 Nutrela Chunks

> “One of my favorite foods is soya chunks. But as I was enjoying some Nutrela today, I noticed a few chunks weren’t quite right.  
> Seems like something’s off with their structure. Could you help me fix these broken chunks so I can enjoy my meal again?”

---

## 🧠 Overview

This challenge revolved around a **corrupted PNG file**.  
Our task was to **repair** the image, understand what was wrong, and finally **recover the hidden flag** embedded in it.

Final Flag → `nite{nOw_yOu_knOw_abOut_PNG_chunk5}`

---

## 🪄 Step-by-Step Solution

### 🔹 Step 1 – Hex Inspection

We first inspected the file using a **hex editor**. A valid PNG must start with:

```
89 50 4E 47 0D 0A 1A 0A
```

However, our file started with:

```
89 70 6E 67 0D 0A 1A 0A
```

The lowercase `p n g` were incorrect.  
We replaced them with uppercase values to restore the PNG signature.

---

### 🔹 Step 2 – Checking File Information

```bash
file nutrela.png
```

Output:

```
nutrela.png: PNG image data, 1000 × 1000, 8-bit RGB non-interlaced
```

So the header looked fine — but the deeper check showed an error:

```bash
pngcheck nutrela.png
```

```
zlib warning: different version (expected 1.2.13, using 1.3)
nutrela.png  illegal reserved-bit-set chunk idat
ERROR: nutrela.png
```

This means our **IDAT chunk** (image data) was broken or incorrectly labeled.

---

### 🔹 Step 3 – Attempting Quick Fix with pngfix

```bash
pngfix --out=fixed.png nutrela.png
```

This produced a very small file (8 bytes).  
So `pngfix` alone couldn’t recover the data — we’d need manual surgery.

---

### 🔹 Step 4 – Extracting Hidden Data Using binwalk

We used **binwalk** to extract embedded or compressed data:

```bash
sudo binwalk -e --run-as=root nutrela.png
```

Result:

```
_nutrela.png.extracted/
├── 29
└── 29.zlib
```

We found a `.zlib` file containing compressed image data.

---

### 🔹 Step 5 – Decompressing the Zlib Stream

```bash
python3 - <<'EOF'
import zlib
data = open("29.zlib","rb").read()
out = zlib.decompress(data)
open("decompressed.bin","wb").write(out)
print("✅ Decompressed → decompressed.bin")
EOF
```

Output:

```
✅ Decompressed → decompressed.bin
```

We verified its structure:

```bash
xxd -g 1 -l 64 decompressed.bin
```

The output showed sequences like `01 ff ff ff`, confirming pixel data.

---

### 🔹 Step 6 – Rebuilding the PNG

We wrote a Python script `rebuild_png.py` to reconstruct the file properly.  
This script rebuilt valid chunks (`IHDR`, `IDAT`, `IEND`) and fixed their CRCs.

```python
import struct, zlib, binascii
def read_chunks(data):
    i = 8; chunks=[]
    while i < len(data):
        if i+8>len(data): break
        length=struct.unpack(">I",data[i:i+4])[0]
        ctype=data[i+4:i+8]; cdata=data[i+8:i+8+length]
        crc=data[i+8+length:i+12+length]
        chunks.append((length,ctype,cdata,crc))
        i += 12+length
    return chunks
def make_chunk(ctype,cdata):
    length=struct.pack(">I",len(cdata))
    crc=struct.pack(">I",binascii.crc32(ctype+cdata)&0xffffffff)
    return length+ctype+cdata+crc
png_sig=b'\x89PNG\r\n\x1a\n'
orig=open("nutrela.png","rb").read()
chunks=read_chunks(orig)
pre=[]; iend=None
for L,T,D,C in chunks:
    if T==b'IDAT': continue
    if T==b'IEND': iend=(L,T,D,C); continue
    pre.append((L,T,D,C))
raw=open("decompressed.bin","rb").read()
new_idat=zlib.compress(raw)
out=bytearray(png_sig)
for L,T,D,C in pre:
    out+=struct.pack(">I",L)+T+D+C
out+=make_chunk(b'IDAT',new_idat)
out+=struct.pack(">I",0)+b'IEND'+b'\xae\x42\x60\x82'
open("reconstructed.png","wb").write(out)
print("Rebuilt → reconstructed.png")
```

---

### 🔹 Step 7 – Adding a Missing IEND Chunk

We discovered our original PNG didn’t contain an **IEND** marker.  
So we added one manually:

```bash
printf '\x00\x00\x00\x00IEND\xae\x42\x60\x82' >> nutrela.png
```

Then ran:

```bash
python3 rebuild_png.py
```

Output:

```
Wrote reconstructed.png (size bytes: 1043004)
```

---

### 🔹 Step 8 – Fixing Chunk Case Sensitivity

```bash
sed -i 's/idat/IDAT/g' reconstructed.png
sed -i 's/iend/IEND/g' reconstructed.png
pngcheck reconstructed.png
```

Output:

```
reconstructed.png  additional data after IEND chunk
ERROR: reconstructed.png
```

Bingo! The image was valid but contained **data hidden after IEND**.

---

### 🔹 Step 9 – Retrieving the Flag

```bash
strings -n 5 reconstructed.png | tail -n 30
```

Output:

```
nite{nOw_yOu_knOw_abOut_PNG_chunk5}
```

---

## 🏁 Final Flag

```
nite{nOw_yOu_knOw_abOut_PNG_chunk5}
```

---

## 🧩 Concepts Learnt

| Concept | Explanation |
|:--|:--|
| **PNG Structure** | A PNG file is made of structured chunks: `IHDR`, `IDAT`, and `IEND`. |
| **Critical vs Ancillary Chunks** | Uppercase = essential; lowercase = optional. |
| **Zlib Compression** | PNG compresses image data using zlib, stored inside IDAT. |
| **CRC Checksums** | Each chunk ends with a 4-byte CRC integrity check. |
| **Extra Data after IEND** | Not allowed by spec, but common trick for hiding flags. |
| **Digital Forensics Tools** | Tools like `binwalk`, `pngcheck`, `xxd`, `strings` help explore and repair files. |

---

## 🧭 Notes

- Initially tried `pngfix` but it produced only 8 bytes.
- Learned that PNG chunk names are **case-sensitive**.
- Used `binwalk` to carve out compressed streams.
- Rebuilt the PNG manually and learned about **CRC** and **zlib** structure.
- The hidden flag was neatly placed after the `IEND` chunk — a CTF classic.

---

## 🔗 References

- [W3C PNG Specification](https://www.w3.org/TR/PNG/)
- [libpng Documentation](https://www.libpng.org/pub/png/libpng.html)
- [pngcheck Utility](https://www.libpng.org/pub/png/apps/pngcheck.html)
- [zlib Format Reference](https://zlib.net/)
- [Binwalk GitHub](https://github.com/ReFirmLabs/binwalk)
- [Foremost Carving Tool](https://github.com/korczis/foremost)

---

## ✅ Conclusion

You successfully:
- Repaired a broken PNG header.
- Extracted and decompressed zlib data.
- Rebuilt valid PNG chunks manually.
- Identified hidden data after IEND.

And finally uncovered the hidden message:

> **nite{nOw_yOu_knOw_abOut_PNG_chunk5}**

---

🎉 **Challenge Completed — Nutrela Chunks (Digital Forensics)**


---

## 🧩 Understanding PNG Chunks (IHDR, IDAT, IEND)

Every PNG file is made up of **chunks** — structured data blocks that define everything from image size to pixels.

### 🧱 PNG Signature
Each PNG starts with the **8-byte signature**:

```
89 50 4E 47 0D 0A 1A 0A
```

It identifies the file as a PNG before the chunks begin.

---

### 🔹 Main Critical Chunks

| Chunk | Full Form | Purpose | Required? |
|:--|:--|:--|:--:|
| **IHDR** | Image Header | Defines width, height, color depth, etc. | ✅ |
| **IDAT** | Image Data | Stores compressed image pixels using zlib | ✅ |
| **IEND** | Image End | Marks the end of the PNG stream | ✅ |

---

### 🧩 IHDR – Image Header
The **first chunk** in every PNG.  
It defines the essential image properties.

| Field | Bytes | Description |
|:--|:--:|:--|
| Width | 4 | Image width in pixels |
| Height | 4 | Image height in pixels |
| Bit depth | 1 | Bits per color sample (usually 8) |
| Color type | 1 | 0=Grayscale, 2=RGB, 3=Palette, 4=Grayscale+Alpha, 6=RGBA |
| Compression method | 1 | Always 0 (zlib/deflate) |
| Filter method | 1 | Always 0 |
| Interlace method | 1 | 0 (none) or 1 (Adam7) |

Example from our image:
```
chunk IHDR at offset 0x0000c, length 13
1000 x 1000 image, 24-bit RGB, non-interlaced
```

---

### 🧩 IDAT – Image Data
Contains the **compressed image pixels**.

- The data inside is **zlib-compressed**.
- There can be multiple IDAT chunks in sequence.
- They all combine into one continuous zlib stream.
- PNG chunk names are **case-sensitive**, so `idat` (lowercase) is *invalid*.

Our file had `idat` → triggering this error:
```
illegal reserved-bit-set chunk idat
```

---

### 🧩 IEND – Image End
The **final chunk** in every PNG.

- Contains **no data** (length = 0)
- Simply marks the end of the file
- Byte sequence:
  ```
  00 00 00 00 49 45 4E 44 AE 42 60 82
  ```

In CTF challenges, creators often append **hidden flags** *after* this chunk — just like our flag.

---

### 🧩 Optional / Ancillary Chunks
Other optional chunks can store extra metadata:

| Chunk | Meaning | Notes |
|:--|:--|:--|
| **PLTE** | Palette | Color palette for indexed-color images |
| **tEXt** | Text | Uncompressed textual data |
| **zTXt** | Compressed text data |
| **iTXt** | Internationalized text (UTF-8) |
| **tIME** | Modification timestamp |
| **gAMA** | Gamma correction information |
| **bKGD** | Suggested background color |

---

### 🔠 Chunk Name Case Rules

Each PNG chunk has **4 ASCII letters**, and their case matters:

| Position | Meaning | Example |
|:--|:--|:--|
| 1st | Uppercase → Critical, Lowercase → Ancillary | `I` in `IHDR` = critical |
| 2nd | Uppercase → Public, Lowercase → Private | `H` = public |
| 3rd | Must always be uppercase (reserved) | |
| 4th | Uppercase → Safe-to-copy, Lowercase → Unsafe | `R` = safe |

So `IHDR` is fully valid.  
Your corrupted `idat` failed because lowercase letters break these rules.

---

### 🧾 TL;DR Summary

| Chunk | Purpose | Example Data | Notes |
|:--|:--|:--|:--|
| **IHDR** | Header info | Size, bit depth, color mode | Always first |
| **IDAT** | Image pixels | zlib-compressed data | Multiple allowed |
| **IEND** | File end marker | 0 bytes | Always last |
| **tEXt** | Metadata | Custom strings | Optional |
| **PLTE** | Palette | Color map | Optional |

---

**In short:** PNGs are modular, self-validating image containers built from well-defined chunks — and understanding these helped us repair `Nutrela.png` perfectly.

---

# Challenge Name: RAR of the Abyss

> Two philosophers peer into the networked abyss and swap a secret. Use the secret to decrypt the Abyss’ RAwR and pull your flag from the void.

---

## Solution

### Step 1: Locate the PCAP file
The file `abyss.pcap` was located in the Downloads folder:
```bash
cd /mnt/c/Users/Dhrisha\ Bhosale/Downloads
ls -l abyss.pcap
file abyss.pcap
```
Output:
```
abyss.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 65535)
```

### Step 2: Install network and extraction tools
We installed all required packages for network forensics and archive extraction.
```bash
apt update -y
apt install -y tcpflow tshark p7zip-full binwalk unrar
```
Tools installed:
- **tcpflow** — reconstructs TCP streams from a PCAP.
- **tshark** — Wireshark CLI tool for packet analysis.
- **p7zip-full** — provides `7z` to extract archives.
- **binwalk** — for scanning binaries for embedded files.
- **unrar** — official RAR extractor with full RAR5 support.

### Step 3: Search for potential secrets
We search inside the PCAP for any plaintext clues:
```bash
strings -a abyss.pcap | egrep -i "Camus|Nietzsche|password|b3y0nd|beyond" | sed -n '1,40p'
```
Output:
```
Camus: One must imagine Sisyphus happy but are we happy ?
Nietzsche: You will be happy after reading my latest work
Camus: whats the password ?
Nietzsche: b3y0ndG00dand3vil
Camus: thanks
```
💡 **Password found:** `b3y0ndG00dand3vil`

### Step 4: Reconstruct TCP flows
We use `tcpflow` to rebuild TCP byte streams from packets:
```bash
mkdir -p flows
tcpflow -r abyss.pcap -o flows
ls -lah flows
```
Output snippet:
```
-rwxrwxrwx 1 root root  286 Oct 22 14:09 010.000.000.020.53003-010.000.000.010.00080
```

### Step 5: Identify file type
Check what’s inside the flow:
```bash
file flows/010.000.000.020.53003-010.000.000.010.00080
```
Output:
```
RAR archive data, v5
```

Inspect header manually:
```bash
hexdump -C flows/010.000.000.020.53003-010.000.000.010.00080 | head -n 20
```
The bytes begin with `52 61 72 21` (`Rar!`), confirming a RAR archive.

### Step 6: Extract the RAR file using the password
Try `7z` (failed with unsupported method):
```bash
7z x flows/010.000.000.020.53003-010.000.000.010.00080 -o/tmp/rar_out_leet -p'b3y0ndG00dand3vil' -y
```
Output:
```
ERROR: Unsupported Method : flag.txt
```

Fallback to `unrar` (works):
```bash
unrar l flows/010.000.000.020.53003-010.000.000.010.00080
unrar x -p'b3y0ndG00dand3vil' flows/010.000.000.020.53003-010.000.000.010.00080 /tmp/rar_unrar_out/
```
Output:
```
Extracting  flag.txt  OK
All OK
```

### Step 7: Read the flag
```bash
cat /tmp/rar_unrar_out/flag.txt
```
Output:
```
nite{thus_sp0k3_th3_n3tw0rk_f0r3ns1cs_4n4lyst}
```

✅ **Flag:** `nite{thus_sp0k3_th3_n3tw0rk_f0r3ns1cs_4n4lyst}`

---

## Concepts Learnt

### 1. PCAP (Packet Capture)
A `.pcap` file stores captured packets with headers and payloads. Tools like Wireshark or tcpflow parse and reconstruct network data from them.

### 2. TCP Streams
TCP ensures reliable byte delivery. A *TCP stream* is a sequence of bytes exchanged between two endpoints. Rebuilding streams helps recover files transmitted over TCP.

### 3. `tcpflow`
This utility reassembles TCP conversations into files (named by IPs and ports).  
Example filename:
```
010.000.000.020.53003-010.000.000.010.00080
```
means **source 10.0.0.20:53003 → destination 10.0.0.10:80**.

### 4. RAR5 and Extraction
RAR5 is a modern archive format supporting strong AES encryption and compressed headers.  
`7z` can detect RAR5 but may fail if using newer compression methods → hence `unrar` was used.

### 5. Network Forensics Workflow
1. Collect packets (`.pcap`)
2. Extract readable text (`strings`)
3. Reconstruct TCP streams (`tcpflow`)
4. Identify embedded files (`file`, `hexdump`)
5. Decrypt/unpack content (`unrar`)
6. Retrieve flag

---

## Notes

- `7z` failed due to **unsupported RAR5 method**.
- The conversation inside the capture directly contained the **password**.
- `tcpflow` helped isolate the binary stream containing the RAR archive.
- The flag file (`flag.txt`) was only 47 bytes.

---

## Resources

- [Wireshark Documentation](https://www.wireshark.org/docs/)
- [tcpflow Manual](https://linux.die.net/man/1/tcpflow)
- [p7zip / 7z Documentation](https://linux.die.net/man/1/7z)
- [unrar Documentation](https://www.rarlab.com/technote.htm)
- [binwalk GitHub](https://github.com/ReFirmLabs/binwalk)

---

## Final Flag

```
nite{thus_sp0k3_th3_n3tw0rk_f0r3ns1cs_4n4lyst}
```

---

## Concepts Summary

| Concept | Explanation |
|----------|--------------|
| PCAP | Captured network packets |
| TCP Stream | Continuous byte flow between two network endpoints |
| tcpflow | Tool to rebuild TCP streams |
| RAR5 | Archive format with optional encryption |
| strings | Command to extract readable text |
| Wireshark/tshark | Tools for network analysis |
| Password | `b3y0ndG00dand3vil` |
| Flag | `nite{thus_sp0k3_th3_n3tw0rk_f0r3ns1cs_4n4lyst}` |

---

# NineTails

> **Description:** Looks like I got a little too clever and hid the flag as a password in Firefox, tucked away like one of NineTails’ many tails. Recover the **logins** and the **key4** and let it guide you to the flag.
>
> **Hint:** I named my Ninetails **"j4gjesg4"**, quite a peculiar name isn't it?

---

## Solution

### Step 1: Initial inspection

- The challenge archive was provided as a `.rar` file.
- Extracting the archive revealed a single file with a `.ad1` extension.

At first glance, this immediately suggested that we were dealing with a **forensic disk image**, not a typical file dump.

---

### Step 2: Identifying the AD1 format

- `.ad1` files are **AccessData Custom Content Images**, commonly used with forensic tools.
- Standard Linux forensic tools (like `tsk_recover`) do **not** natively support this format.
- Because of this, attempting to process the image using SleuthKit-based tools resulted in errors.

✅ **Correct approach:** Use **FTK Imager**, which fully supports AD1 images.

---

### Step 3: Loading the image in FTK Imager

- Open **FTK Imager**
- Navigate to **File → Add Evidence Item**
- Select **Image File**
- Choose the provided `ninetails.ad1` file

Once loaded, FTK Imager allowed us to cleanly browse the filesystem contained inside the disk image.

---

### Step 4: Locating the Firefox profile

From the challenge description, we were explicitly told:
- The flag is stored as a **Firefox saved password**
- The Firefox profile is named **`j4gjesg4`**

Knowing how Firefox stores local browser data, we navigated to:

```
AppData/Roaming/Mozilla/Firefox/Profiles/j4gjesg4.default-release
```

This directory contained the critical Firefox files:
- `logins.json`
- `key4.db`
- `cert9.db`

These three files together are required to decrypt stored Firefox credentials.

---

### Step 5: Exporting the Firefox profile

- The entire `j4gjesg4.default-release` directory was exported from FTK Imager
- The extracted folder was copied to our local system for analysis

At this stage, we had everything required to decrypt Firefox credentials offline.

---

### Step 6: Decrypting stored credentials

Firefox encrypts saved passwords locally using keys stored in `key4.db`.
To decrypt them, we used the following open-source tool:

```
https://github.com/unode/firefox_decrypt
```

#### Running the tool

```bash
C:\Users\adt10\Downloads>python firefox_decrypt.py j4gjesg4.default-release
```

Output:

```
2025-12-04 14:52:01,860 - WARNING - Running with unsupported encoding 'locale': cp1252
2025-12-04 14:52:01,916 - WARNING - profile.ini not found
2025-12-04 14:52:01,916 - WARNING - Continuing and assuming 'j4gjesg4.default-release' is a profile location

Website:   https://www.rehack.xyz
Username: 'warlocksmurf'
Password: 'GCTF{m0zarella'

Website:   https://ctftime.org
Username: 'ilovecheese'
Password: 'CHEEEEEEEEEEEEEEEEEEEEEEEEEESE'

Website:   https://www.reddit.com
Username: 'bluelobster'
Password: '_f1ref0x_'

Website:   https://www.facebook.com
Username: 'flag'
Password: 'SIKE'

Website:   https://warlocksmurf.github.io
Username: 'Man I Love Forensics'
Password: 'p4ssw0rd}'
```

Despite a few warnings, the tool successfully decrypted all saved credentials.

---

### Step 7: Reconstructing the flag

Observing the passwords carefully:

- `GCTF{m0zarella`
- `_f1ref0x_`
- `p4ssw0rd}`

Combining the meaningful fragments gives the final flag.

---

## Flag

```
GCTF{m0zarella_f1ref0x_p4ssw0rd}
```

---

## Concepts learnt

- Understanding and handling **AD1 forensic disk images**
- Using **FTK Imager** to browse and export forensic evidence
- Firefox credential storage architecture (`logins.json`, `key4.db`, `cert9.db`)
- Offline browser password decryption
- Importance of understanding application-specific artefact locations in forensics

---

## Notes (Mistakes & Dead Ends)

- Initially assuming SleuthKit tools would work on AD1 images
- Trying to carve browser artefacts instead of locating intact Firefox profiles
- Ignoring the hint initially and searching globally instead of targeting the `j4gjesg4` profile

Once the correct forensic workflow was followed, the challenge became straightforward.

---

## Resources

- Firefox Decrypt Tool: https://github.com/unode/firefox_decrypt
- FTK Imager: https://www.exterro.com/digital-forensics-software/ftk-imager


---

# 1. ReDraw – Windows Memory Forensics Challenge

> A multi-stage Windows memory forensics challenge where a crashed Windows 7 machine’s RAM dump is analyzed to recover evidence from command-line usage, archived files, and an MS Paint canvas left behind in memory.

---

## Solution:

### Step 1: Identify Memory Image Profile

The first step was to determine the correct Windows profile for the memory dump.

```bash
./vol -f MemoryDump_Lab1.raw imageinfo
```

This revealed the system as **Windows 7 SP1 x64**, which was used for all further analysis.

---

### Step 2: Scanning Files from Memory

We searched for files present in memory using:

```bash
./vol -f MemoryDump_Lab1.raw --profile=Win7SP1x64 filescan
```

Filtering for the user **Alissa Simpson** revealed several interesting files, including an archive named **Important.rar**.

```bash
./vol -f MemoryDump_Lab1.raw --profile=Win7SP1x64 filescan | grep "Alissa Simpson"
```

---

### Step 3: Extracting the RAR File

After identifying the memory offset of `Important.rar`, it was dumped from RAM:

```bash
./vol -f MemoryDump_Lab1.raw --profile=Win7SP1x64 dumpfiles \
-Q 0x000000003fac3bc0 --name importantFile.rar -D importantstuff/
```

Inside the RAR file was a **flag image**, protected by a password.

---

### Step 4: Cracking the Archive Password

To retrieve the password, Windows password hashes were extracted:

```bash
./vol -f MemoryDump_Lab1.raw --profile=Win7SP1x64 hashdump | grep Alissa
```

The NTLM hash was reused directly as the password:

```
F4FF64C8BAAC57D22F22EDC681055BA6
```

Using this password unlocked the archive.

---

### Step 5: Investigating the Black Command Window (Stage 1 Flag)

Since the prompt indicated a command window flickered before the crash, running processes were inspected:

```bash
./vol -f MemoryDump_Lab1.raw --profile=Win7SP1x64 pslist
```

The presence of `cmd.exe` matched the clue. Command history was recovered using:

```bash
./vol -f MemoryDump_Lab1.raw --profile=Win7SP1x64 consoles
```

This revealed a Base64-encoded string, which decoded to the first flag.

---

### Step 6: Recovering MS Paint Data (Stage 3)

The system had **mspaint.exe** running at the time of the crash.

The process memory was dumped:

```bash
./vol -f MemoryDump_Lab1.raw --profile=Win7SP1x64 memdump -p 2424 -D importantstuff
```

The resulting `.dmp` file was renamed and opened in **GIMP** as raw image data. By experimenting with width, height, and color settings, the original MS Paint canvas was reconstructed and clearly showed the final flag.

---

## Flag:

```
flag{th1s_1s_th3_1st_st4g3!!}

flag{w3ll_3rd_stage_was_easy}

flag{Good_BoY_good_girl}
```

---

## Concepts learnt:

- Memory dump analysis fundamentals
- Using Volatility 2 for Windows forensics
- Extracting files directly from RAM
- NTLM hash usage and password recovery
- Investigating command-line artifacts
- Recovering graphical application data from process memory

---

## Notes:

- Setting up Volatility 2 required manual installation
- Interpreting raw MS Paint memory required trial and error
- Multiple plugins revealed overlapping evidence

Volatility setup steps used:

```bash
wget http://downloads.volatilityfoundation.org/releases/2.6/volatility_2.6_lin64_standalone.zip
unzip volatility_2.6_lin64_standalone.zip
mv volatility_2.6_lin64_standalone/volatility_2.6_lin64_standalone ./vol
chmod +x ./vol
```

---

## Resources:

- https://infosecwriteups.com/memory-dump-analysis-by-using-volatility-framework-742d70663d41
- https://hacktivity.fr/volatility-2-windows-cheatsheet/

