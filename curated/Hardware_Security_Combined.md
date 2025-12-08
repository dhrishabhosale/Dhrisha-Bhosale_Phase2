# Hardware Security

# 1. I Like Logic More

> Hardware Security Challenge — analyzing microSD communication using Saleae Logic 2

---

## Challenge Description

We were given a Saleae Logic capture (.sal) containing digital waveforms captured from a microSD card interface.
The objective was to analyze the signals and extract a hidden flag.

Because of the challenge name “I Like Logic More”, it was initially unclear whether the task involved:
- Boolean logic / logic gates, or
- The Saleae Logic 2 software and protocol analysis

This ambiguity directly caused multiple mistakes early in the analysis.

---

## Complete Step-by-Step Analysis (Including All Mistakes)

### Mistake 1: Assuming Boolean / Logic Gate Challenge

The first assumption was that the challenge focused on:
- Truth tables
- Boolean equations
- Logic gate reconstruction

Time was spent attempting to correlate channels as inputs and outputs.

**Why this failed:**
The waveform showed high-frequency burst patterns rather than steady logic levels. This behavior is characteristic of serial communication, not combinational logic.

**Lesson learned:**  
Always determine whether signals represent communication or computation before deeper analysis.

---

### Mistake 2: Blind Protocol Guessing

Without identifying the protocol visually, several analyzers were attempted:
- UART
- I²C
- Manual CSV analysis
- Python brute-force decoding

These attempts produced:
- Garbage output
- Repeating 0xFF / 0x00 bytes
- No readable ASCII

**Lesson learned:**  
Protocol analyzers only work when the correct protocol is chosen.

---

### Mistake 3: Repeated Incorrect SPI Channel Mapping

Once SPI was suspected, channel roles were still mapped incorrectly multiple times.

| Attempt | CLK | CS | MOSI | MISO | Result |
|-------|----|----|----|----|--------|
| 1 | D0 | D3 | D1 | D2 | Only idle bytes |
| 2 | D2 | D3 | D0 | D1 | Garbage output |
| 3 | D0 | D1 | D2 | D3 | No ASCII |
| 4 | D0 | None | D1 | D2 | Random noise |

**Lesson learned:**  
Clock and Chip Select must be identified visually before assigning data lines.

---

### Mistake 4: Fighting Automation Instead of Using the GUI

Significant time was spent trying:
- logic2-automation scripts
- gRPC connections
- Manual binary parsing

This resulted in environment issues, connection errors, and unnecessary complexity.

**Lesson learned:**  
Always use the Saleae Logic GUI analyzers first. Automate only after understanding the signals.

---

## Correct Identification of SPI Signals

After carefully inspecting the waveforms:

- **CLK (D3):** Clean, regular square-wave bursts
- **CS / Enable (D2):** Active-low framing signal
- **MOSI (D1):** Toggles with clock when CS is low
- **MISO (D0):** Responds only during active CS

### Final SPI Mapping

| Signal | Channel |
|------|---------|
| CLK | D3 |
| CS (Active Low) | D2 |
| MOSI | D1 |
| MISO | D0 |

SPI Configuration:
- Mode 0 (CPOL = 0, CPHA = 0)
- MSB first
- 8 bits per transfer

---

## Decoding the Data

Once the correct SPI configuration was applied in Logic 2:

1. The SPI analyzer decoded valid frames
2. ASCII output was enabled
3. The data table was exported as CSV

Readable text appeared in the decoded output:

DATA_IS_GOOD_2_LOGIC

Continuing through the decoded data revealed the complete flag.

---




---

## Final Flag

HTB{unp2073c73d_532141_p2070c015_0n_53cu23_d3v1c35}

---

## Summary of All Mistakes Made

1. Misinterpreting the challenge as Boolean logic
2. Guessing protocols without waveform analysis
3. Multiple incorrect SPI channel assignments
4. Ignoring CS polarity
5. Treating idle SPI traffic as meaningful data
6. Over-engineering with scripts instead of GUI tools
7. Losing time due to frustration instead of reassessing assumptions

Each mistake directly contributed to understanding proper hardware analysis methodology.

---

## Final Working Configuration

- Protocol: SPI
- Mode: 0 (CPOL = 0, CPHA = 0)
- CLK: D3
- CS: D2 (Active Low)
- MOSI: D1
- MISO: D0
- Bit Order: MSB First
- Data Width: 8 bits
- Output: Hex + ASCII

---

## Concepts Learned

- microSD cards communicate using SPI
- How to visually identify SPI signals
- Importance of Chip Select framing
- Proper use of Saleae Logic 2 analyzers
- Why brute-force decoding is ineffective
- Importance of challenging assumptions early

---

## References

- https://electronics.stackexchange.com/questions/232885/how-does-an-sd-card-communicate-with-a-computer
- https://support.saleae.com/product/user-guide/protocol-analyzers/analyzer-user-guides/using-spi
- https://zeroalpha.com.au/services/data-recovery-blog/sd/sd-and-micro-sd-pinout-description-including-spi-protocol


---

# 1. Challenge Name  
**Red Devil**

> **Challenge Description**  
> *this is the worst football team ever (i dont even watch football lmeow)*  

---

## Solution:

We are provided with a raw RF capture file named **`signal.cf32`**.  
The goal is to decode this signal and recover the hidden flag.

This challenge involves **Software Defined Radio (SDR)** concepts and RF signal decoding.

---

### Step 1: Understanding the File Format

- The `.cf32` extension indicates **32-bit complex floating‑point IQ samples**.
- Each sample contains:
  - **I** (In-phase)
  - **Q** (Quadrature)
- These files are commonly produced by SDR software such as GNU Radio or RTL‑SDR tools.

This immediately tells us that the challenge involves **radio signal analysis**.

---

### Step 2: Initial Approach & Avg Dhrisha Mistakes

Initially, we attempted a **manual decoding approach**:

- Loaded the signal in **Inspectrum**
- Tried to:
  - Identify symbol timing
  - Manually extract bits
  - Reconstruct data from I/Q and amplitude plots
  - Brute‑force binary images from extracted bitstreams

This led to:
- Thousands of generated files
- Confusing bit alignment
- No clear ASCII output
- Excessive time complexity

 **Mistake:** Overcomplicating the problem and ignoring protocol‑aware tools.

---

### Step 3: Correct Tool — `rtl_433`

We then identified that **`rtl_433`** is designed exactly for tasks like this.

It can:
- Analyze unknown RF captures
- Detect modulation & encoding
- Automatically decode many common RF protocols

---

### Step 4: Analyzing the Signal

Run `rtl_433` in analyzer mode:

```bash
rtl_433 -A signal.cf32
```

Relevant output:

```text
Detected OOK package
Guessing modulation: Manchester coding
bitbuffer:: Number of rows: 1
[00] {256} 2a aa aa aa 0c 4e 48 54 42 7b 52 46 5f 48 34 63 6b 31 6e 36 5f 31 73 5f 63 30 30 6c 21 21 21 7d
```

Key observations:
- **Modulation:** OOK (On‑Off Keying)
- **Encoding:** Manchester Coding
- **Payload:** Hex‑encoded data

---

### Step 5: Decoding the Payload

Extracted hex:

```text
48 54 42 7b 52 46 5f 48 34 63 6b 31 6e 36 5f 31 73 5f 63 30 30 6c 21 21 21 7d
```

Convert hex → ASCII:

```text
HTB{RF_H4ck1n6_1s_c00l!!!}
```

---

## Flag:

```text
HTB{RF_H4ck1n6_1s_c00l!!!}
```

---

## Concepts learnt:

- **Software Defined Radio (SDR)**
- **IQ (In‑phase & Quadrature) data**
- **OOK modulation**
- **Manchester Encoding**
- **Protocol‑aware RF decoding**
- Using `rtl_433` analyzer mode

---

## Notes:

- Manual decoding is useful but not always efficient
- Using the right tool saves massive effort
- This challenge was intentionally solvable with `rtl_433`

Alternate tools:
- GNU Radio
- Universal Radio Hacker (URH)
- Custom DSP scripts in Python

---

## Resources:

- [rtl_433 GitHub](https://github.com/merbanan/rtl_433)
- [rtl_433 Pulse Viewer](https://triq.org/pdv/)
- [Manchester Encoding](https://en.wikipedia.org/wiki/Manchester_code)
- [On‑Off Keying](https://en.wikipedia.org/wiki/On%E2%80%93off_keying)

***


---

# Formwear – Firmware Analysis Write‑Up

## 1. Challenge Overview

This challenge provided a firmware update archive and required me to analyze its contents to recover a flag. The main idea was to treat the firmware as a normal filesystem image, mount it, and then explore its internal configuration files to find anything that looked like credentials or a flag.

## 2. Files Provided

After extracting the main archive `formwear.zip`, I found three files:

- `fwu_ver`
- `hw_ver`
- `rootfs`

I first used the `file` command to understand what each file actually was:

```bash
Dhrisha@Dell-Inspiron:~$ file fwu_ver
fwu_ver: ASCII text
Dhrisha@Dell-Inspiron:~$ file hw_ver
hw_ver: X1 archive data
Dhrisha@Dell-Inspiron:~$ file rootfs
rootfs: Squashfs filesystem, little endian, version 4.0, zlib compressed, 10936182 bytes, 910 inodes, blocksize: 131072 bytes, created: Sun Oct  1 07:02:43 2023
```

### Interpretation

- **`fwu_ver`**  
  The `file` output shows that this is simple ASCII text, so it likely contains the firmware version.

- **`hw_ver`**  
  Identified as “X1 archive data”. This indicates it’s some sort of small metadata/archive related to hardware version.

- **`rootfs`**  
  This is the important one. It’s recognized as a **SquashFS filesystem**. SquashFS is a compressed, read-only filesystem commonly used in embedded devices and firmware images. That means `rootfs` is essentially the full root filesystem of the device.

## 3. Inspecting the Simple Files

I checked the straightforward text files using `cat`:

```bash
Dhrisha@Dell-Inspiron:~$ cat fwu_ver
3.0.5
Dhrisha@Dell-Inspiron:~$ cat hw_ver
X1
```

From this I learned:

- Firmware version: **3.0.5**
- Hardware version: **X1**

These values are interesting to know but don’t directly reveal the flag. The real target is inside the `rootfs` filesystem.

## 4. Mounting the Firmware Filesystem

Since `rootfs` is a SquashFS filesystem, I needed to mount it to inspect its contents. I created a mount directory and mounted it in read‑only loopback mode:

```bash
Dhrisha@Dell-Inspiron:~$ mkdir mnt
Dhrisha@Dell-Inspiron:~$ sudo mount -o ro,loop rootfs mnt
```

- `mkdir mnt` creates a folder to act as the mount point.
- `sudo mount -o ro,loop rootfs mnt` tells the system:
  - **`-o ro`** – mount as read‑only (safe, we don’t want to modify firmware).  
  - **`loop`** – treat the file (`rootfs`) as a block device and mount it.  
  - `rootfs` – the SquashFS image file.  
  - `mnt` – the directory where the filesystem will appear.

After mounting, I listed the contents:

```bash
Dhrisha@Dell-Inspiron:~/mnt$ ls -la
total 4
drwxrwxr-x 14 root   root    257 Aug 10  2022 .
drwxr-x--- 16 Dhrisha Dhrisha 4096 Nov 29 14:20 ..
-rw-rw-r--  1 root   root      0 Aug 10  2022 .lstripped
drwxrwxr-x  3 root   root   3225 Aug 10  2022 bin
lrwxrwxrwx  1 root   root     13 Aug 10  2022 config -> ./var/config/
drwxrwxr-x  2 root   root   3091 Aug 10  2022 dev
drwxrwxr-x  7 root   root    926 Oct  1  2023 etc
drwxrwxr-x  3 root   root     31 Oct  1  2023 home
drwxrwxr-x  2 root   root      3 Oct  1  2023 image
drwxrwxr-x  6 root   root   2580 Aug 10  2022 lib
lrwxrwxrwx  1 root   root      8 Aug 10  2022 mnt -> /var/mnt
drwxrwxr-x  2 root   root      3 Aug 10  2022 overlay
drwxrwxr-x  2 root   root      3 Aug 10  2022 proc
drwxrwxr-x  2 root   root      3 Aug 10  2022 run
lrwxrwxrwx  1 root   root      4 Aug 10  2022 sbin -> /bin
drwxrwxr-x  2 root   root      3 Aug 10  2022 sys
lrwxrwxrwx  1 root   root      8 Aug 10  2022 tmp -> /var/tmp
drwxrwxr-x  3 root   root     28 Aug 10  2022 usr
drwxrwxr-x  2 root   root      3 Aug 10  2022 var 
```

### Observations

- The structure looks like a typical embedded Linux filesystem: `bin`, `etc`, `lib`, `home`, `usr`, `var`, etc.
- There is a **symlink** called `config` pointing to `./var/config/`:
  ```
  config -> ./var/config/
  ```
- There are other symlinks like:
  - `mnt -> /var/mnt`
  - `sbin -> /bin`
  - `tmp -> /var/tmp`

Symlinks in these systems are often used to keep paths flexible and to separate read‑only firmware from writable overlays.

## 5. Following the Configuration Trail

The `config` symlink suggested that configuration files live under `var/config/`. However, when checking `/var`, it initially appeared empty or minimal. This is common in firmware images where some directories are meant to be populated at runtime (in RAM or flash overlay).

Despite that, I knew that configuration is a good place to hide credentials or flags, especially in XML or text-based files. So I searched within the mounted filesystem for files related to “config”.

During this search, I located a file named **`config_default.xml`**. This kind of file usually contains factory default settings for the firmware, such as default usernames, passwords, and other parameters.

## 6. Inspecting `config_default.xml`

When I opened `config_default.xml`, I saw a lot of XML data defining various configuration values for the device. Among these values, I specifically looked for anything resembling a flag format (typically enclosed in braces `{}` in CTFs).

I searched inside the XML for `{` and found the following snippet:

```xml
<Value Name="SUSER_NAME" Value="admin"/>
<Value Name="SUSER_PASSWORD" Value="HTB{N0w_Y0u_C4n_L0g1n}"/>
```

### Interpretation

- `SUSER_NAME` – likely stands for “Super User Name” or “System User Name”.  
  - Value: `admin`  
- `SUSER_PASSWORD` – likely the corresponding password for that user.  
  - Value: `HTB{N0w_Y0u_C4n_L0g1n}`

The value clearly follows a typical Hack The Box (HTB) flag format, so this matched exactly what I was looking for.

## 7. Recovered Flag

```text
HTB{N0w_Y0u_C4n_L0g1n}
```

This password/flag appears as the default superuser password in the firmware configuration.

## 8. Concepts Learnt / Revisited

During this challenge, I reinforced and learned the following concepts:

- **Working with firmware filesystem images**
  - Recognizing **SquashFS** as a common read‑only filesystem for embedded systems.
  - Understanding that firmware images often contain a full Linux root filesystem packed into a single file like `rootfs`.

- **Mounting a filesystem image**
  - Using `sudo mount -o ro,loop rootfs mnt` to mount the filesystem image safely in read‑only mode.
  - The idea of using `loop` to treat a regular file as a virtual block device.

- **Exploring Linux directory structures**
  - Navigating typical directories like `/bin`, `/etc`, `/home`, `/usr`, and `/var`.
  - Understanding that `/var` is often used for variable data and may appear empty in a static snapshot or before runtime initialization.

- **Symlinks (symbolic links)**
  - Seeing how `config` was a symlink to `./var/config/`.
  - Recognizing that symlinks in firmware can redirect you to the actual locations where important data is stored or expected to be stored.

- **Configuration files as a goldmine**
  - Realizing that `config_default.xml` (and similar configuration files) often store:
    - Default usernames
    - Default passwords
    - Other sensitive or interesting values
  - Using simple pattern searches (like searching for `{`) to quickly locate potential flags.

## 9. Notes and Observations

- Exploring the `/home` directory initially gave some hope, but it turned out that the real key was hidden in the configuration path. It was a reminder not to fixate only on “obvious” locations; config and etc directories are often more promising.
- The flag being stored as a **default superuser password** fits real‑world scenarios, where embedded devices sometimes ship with hard-coded admin credentials in their firmware.
- This challenge was a good practical exercise in:
  - Unpacking firmware
  - Mounting and examining root filesystems
  - Systematically searching for sensitive information or flags inside configuration files.

---

**Summary:**  
I treated the `rootfs` file as a SquashFS filesystem, mounted it, explored the directory structure, followed the configuration symlink, and inspected `config_default.xml`. Inside that file, I found the default superuser password, which doubled as the CTF flag:

`HTB{N0w_Y0u_C4n_L0g1n}`


---


# 1. Speed Thrills But Kills

> *"i recently got involved in a hit and run case in pune, that kid’s porsche was going wayy too fast, if only i knew what the VIN of the car was :("*

The challenge provides a **single file**:
- `trace_captured.sal`

This file is a Saleae Logic Analyzer capture containing raw electrical signals.  
The goal is to analyze this capture and recover the **VIN**, which is embedded as the final **flag**.

---

## Solution:

### 0. Breaking down the challenge hint

Before opening any tools, we analyze the hint:

- Keywords: **car**, **Porsche**, **VIN**, **hit and run**
- VIN (Vehicle Identification Number) is a **17-character identifier**
- Modern cars expose VIN information via **OBD-II**
- OBD-II commonly communicates over **CAN bus**

This already heavily hints that:
> The capture contains **automotive CAN bus traffic**, and the VIN is present inside it.

---

### 1. Understanding the given file (`.sal`)

The `.sal` extension is used by **Saleae Logic / Logic 2**, which is a:
- Logic analyzer tool
- Used to capture and decode digital communication protocols

So the correct first step:

1. Open **Logic 2**
2. `File → Open Capture → trace_captured.sal`

---

### 2. Inspecting available channels

Once the capture is opened, several channels are visible:

- **D0 (Digital Channel 0)**  
  - Very dense activity
  - Constant transitions
- **D1 (Digital Channel 1)**  
  - Mostly idle
- **A0 / A1 (Analog Channels)**  
  - Analog representations of the same signals

Observation:
> Only **D0** shows continuous, meaningful digital communication.

✅ **Conclusion:**  
All useful data is on **D0**.

---

### 3. First wrong assumption: UART (Async Serial)

#### Why UART was tested

- The waveform appears uniform and clock-like
- UART is frequently used in embedded systems
- Logic 2 provides an easy Async Serial analyzer

#### What was done

1. Add **Async Serial** analyzer
2. Configure:
   - Channel: D0
   - Data bits: 8
   - Parity: None
   - Stop bits: 1
3. Try common baud rates:
   - 9600
   - 115200
   - 500000

#### What went wrong

- Decoded output consisted of:
  - `0xFF`
  - `0x80`
  - `0x00`
- No readable ASCII
- No recognizable patterns
- No `HTB{}`-style flag

❌ **Conclusion:**  
This is not UART.

**Mistake learned:**  
A waveform being “dense” does not automatically mean UART.

---

### 4. Second wrong assumption: SPI

#### Why SPI was briefly considered

- Repetitive byte patterns often appear in SPI
- Seen in other hardware challenges

#### Why SPI was ruled out

- SPI requires:
  - Clock (CLK)
  - Chip Select (CS)
  - Data line(s)
- The capture only shows **one usable digital line**
- No clock-like square wave is present

❌ **Conclusion:**  
SPI decoding is impossible here.

---

### 5. Re-reading the hint → correct protocol reasoning

At this point, we stop guessing protocols and **re-evaluate context**:

- The challenge is about a **car**
- VIN extraction
- Automotive diagnostics

✅ Automotive diagnostics = **OBD-II**  
✅ OBD-II = **CAN bus**

This is the critical mental reset that leads to the correct solution.

---

### 6. Measuring bit timing (instead of guessing)

Before decoding CAN, we must determine the **bitrate**.

#### Steps in Logic 2:

1. Zoom in on **D0**
2. Enable **time measurement cursors**
3. Measure distance between two consecutive identical bit edges

#### Measured value:

- Bit width ≈ **8 microseconds (µs)**

#### Calculation:

```
bitrate = 1 / bit_time
        = 1 / 8µs
        ≈ 125000 bits/sec
```

✅ **CAN bitrate = 125 kbps**  
This is a standard automotive CAN speed.

---

### 7. Adding CAN Analyzer correctly

1. Open **Analyzers**
2. Add **CAN Analyzer**
3. Configure:
   - Channel: D0
   - Bitrate: 125000

Results:
- Frames decode perfectly
- Valid IDs
- No framing / CRC errors

✅ This confirms both:
- Correct protocol
- Correct bitrate

---

### 8. Understanding CAN frame data

A CAN frame contains:
- Arbitration ID
- DLC (number of bytes)
- Payload (up to 8 bytes)

VIN data is typically transferred as **ASCII bytes** across several frames.

By default, Logic shows:
- Payload in **hexadecimal**

But hex values can represent ASCII characters.

---

### 9. Switching payload display to ASCII

To reveal readable text:

1. Change CAN payload view from **Hex → ASCII**
2. Scroll through decoded frames

Suddenly, readable text appears.

One sequence clearly shows:

```
HTB{v1n_c42_h4ck1n9_15_1337!*0^}
```

This matches:
- CTF flag format
- VIN-themed wording

---

### 10. Verifying via CSV export

To eliminate any doubt:

1. Export CAN analyzer data as **CSV**
2. Open file in editor
3. Search for `HTB{`

The exact same string appears.

✅ Verification complete.

---

## Flag:

```
HTB{v1n_c42_h4ck1n9_15_1337!*0^}
```

---

## Concepts learnt:

### CAN Bus
- Automotive communication protocol
- Message-based (not point-to-point)
- Uses IDs instead of addresses

### OBD-II
- On-Board Diagnostics interface
- Exposes VIN and vehicle telemetry
- Runs over CAN on modern vehicles

### Bitrate Extraction
- Pulse width measurement
- Eliminates guessing protocol speed

### Logic Analyzer Skills
- Protocol identification
- Analyzer configuration
- ASCII vs Hex interpretation
- CSV export for verification

---

## Notes:

- UART decoding failed due to wrong framing
- SPI decoding failed due to missing clock
- Guessing baud rates wasted time
- Measuring bit timing was the breakthrough
- Context > brute force

---

## Resources:

- https://www.csselectronics.com/pages/obd2-explained-simple-intro
- https://en.wikipedia.org/wiki/CAN_bus
- https://www.youtube.com/watch?v=IyGwvGzrqp8
- https://www.youtube.com/watch?v=9sas4uW4-Vg&t=808s

***


---

# 1. Gates of Mayhem

> iqtest but its on steriods and you have weird aah inputs aswell.

This challenge provided a transistor-level schematic and a CSV file containing sequences of binary inputs.  
The goal was to understand the logic implemented by the circuit and use it to recover the hidden flag.

---

## Solution:

### Step 1: Understanding the Challenge Files

We were given:
- A **KiCad schematic** (`Gates_of_Mayhem`) containing a complex network of BC107 transistors.
- A **CSV file** (`input_sequence.csv`) with six binary inputs per row: `IN1` to `IN6`.

At first glance, the circuit looked intimidating, leading to the hint that this was an *"IQ test on steroids"*.

---

### Step 2: Initial (Incorrect) Assumption

Initially, we assumed:
- Since there are **6 inputs**, each row might directly represent a **6-bit value**.
- 6 bits map neatly to **Base64 indices (0–63)**.

This led us to try decoding the CSV rows directly as Base64 values.



### Step 3: Analyzing the Transistor Circuit

We studied how **NPN transistors** behave in digital logic:
- Conduct (ON) when base input is HIGH
- Pull-down output lines to ground when active

By grouping transistors and tracing current paths, we identified standard logic gates:
- AND gates
- OR gates
- An XOR gate at the final stage (not immediately obvious)

Below is the reduced logic representation derived from the schematic:

![Logic Reduction](https://github.com/user-attachments/assets/8acb1855-fdcf-4abd-a02b-572d1bd74caf)

From this analysis, the full Boolean logic was derived as:

```
OUT = (IN1 AND IN2) XOR ((IN3 AND IN4) AND (IN5 OR IN6))
```

This step was the **core of the challenge**.

---

### Step 4: Implementing the Logic in Python

Once the Boolean expression was known, we could apply it programmatically to each row of the CSV file.

```python
import csv

output_bits = ""

with open("input_sequence.csv", mode="r") as csvfile:
    reader = csv.DictReader(csvfile)

    for row in reader:
        in1 = int(row["IN1"])
        in2 = int(row["IN2"])
        in3 = int(row["IN3"])
        in4 = int(row["IN4"])
        in5 = int(row["IN5"])
        in6 = int(row["IN6"])

        part1 = in1 & in2
        part2 = (in3 & in4) & (in5 | in6)
        result = part1 ^ part2

        output_bits += str(result)

print(output_bits)
```

This script generates a long binary string composed of the circuit’s output for each input row.

---

### Step 5: Converting Binary to Text

The output bitstream was then grouped into 8-bit chunks and converted into ASCII characters:

```python
text = "".join(
    chr(int(output_bits[i:i+8], 2))
    for i in range(0, len(output_bits), 8)
)
print(text)
```

**Terminal Output:**
```
0110001101101001011101000110000101100100011001010110110001111011001100010101111101101100001100000111011000110011010111110111010000110000010111110011001101111000011100000110110000110000001100010111010001011111011011000011000001100111001100010110001101111101

```

---

## Flag:

```
citadel{1_l0v3_t0_3xpl01t_l0g1c}
```

---

## Concepts learnt:

- How transistor-level circuits can implement logic gates
- Manually reducing transistor circuits into Boolean expressions
- Practical understanding of XOR gate behavior when not explicitly labeled
- Reading and processing CSV input in Python
- Binary-to-ASCII decoding

---

## Notes:

- A major incorrect path was assuming the inputs directly represented Base64 data.
- The XOR gate was not explicitly marked in the schematic and required careful truth-table analysis.
- Manually validating the circuit behavior for edge cases helped confirm the final logic.
- This challenge reinforced the importance of trusting *hardware logic* over pattern-matching shortcuts.

---

## Resources:

- [Transistors as Logic Gates](https://youtu.be/OWlD7gL9gS0?si=09IodCWZqtj7mhic)
- [Understanding XOR Gates](https://youtu.be/eYGM3XEIpHg?si=ObEMaoFRrgwY7mp-)

***


---

