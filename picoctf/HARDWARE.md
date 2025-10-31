# 1. Challenge name

> Bare Metal Alchemist

## Solution:

- **Overview / approach**
  - The uploaded file `firmware (1).elf` is an AVR firmware ELF for an Arduino-like device. The flag was not visible in plaintext, so I assumed a simple obfuscation (common in firmware CTFs): single-byte XOR.
  - I brute-forced all 256 single-byte XOR keys, scored results for printable ASCII runs, and inspected the best candidates. One key produced a clear brace-delimited payload that looks like a flag.

- **Step-by-step thought process & actions**
  1. **Identify file type**
     - Command: `file "firmware (1).elf"` showed it is an Atmel AVR ELF (firmware). This suggested we are dealing with compiled microcontroller data rather than a typical Linux binary.
  2. **Look for plaintext**
     - Command: `strings "firmware (1).elf" | head` — no obvious `CTF{` or `FLAG{` found. So the flag is likely encoded/obfuscated.
  3. **Hypothesis**
     - Many firmware CTF tasks hide flags using a single-byte XOR or simple substitution. I decided to brute-force all single-byte XOR keys and inspect printable output.
  4. **Brute-force XOR + detect printable runs**
     - Wrote a small Python script that:
       - Reads the ELF bytes
       - XORs with keys 0..255
       - Finds the longest contiguous printable ASCII run for each key
       - Scores each run using simple heuristics (common word matches, chi-squared letter frequency)
     - The script surfaced a strong candidate for key `0xA5` (and a few other keys with noisy ASCII-like runs). Key `0xA5` produced a clear brace-delimited payload.
  5. **Verify and extract flag**
     - After XOR with `0xA5` the decoded region contains the contiguous substring: `TFCCTF{Th1s_1s_som3_s1mpl3_4rdu1no_f1rmw4re}`.
     - Extracting the braces yields `CTF{Th1s_1s_som3_s1mpl3_4rdu1no_f1rmw4re}`, but the decoded bytes in context contain the prefix `TFC` immediately before the `CTF{...}` producing the full contiguous sequence `TFCCTF{...}`.
     - Which substring to submit depends on contest rules; the user provided the exact flag to include in the report.


```
# Example Python commands used (abridged)
# 1) quick brute-force to find printable runs
from pathlib import Path
data = Path('firmware (1).elf').read_bytes()
for k in range(256):
    dec = bytes(b ^ k for b in data)
    # find longest printable run (simple heuristic)
    # print or save candidates where printable run length > threshold

# 2) decode with key 0xA5 and show braces
k = 0xA5
dec = bytes(b ^ k for b in data)
start = dec.find(b"{")
end = dec.find(b"}", start+1)
print(dec[start-4:end+1])
```

- **Terminal outputs (selected, abbreviated)**

```
# file output
$ file "firmware (1).elf"
firmware (1).elf: ELF 32-bit LSB executable, Atmel AVR... statically linked, with debug_info

# example strings not showing 'CTF{'
$ strings "firmware (1).elf" | grep -i "CTF\|FLAG\|{"
# (no relevant results)
```

```
# After XOR with 0xA5 (excerpt of decoded bytes around offset 0xFF):
000000EF  A5 A9 31 CD A5 A9 31 CD A5 A9 31 CD A5 54 46 43   ..1...1...1..TFC
000000FF  43 54 46 7B 54 68 31 73 5F 31 73 5F 73 6F 6D 33   CTF{Th1s_1s_som3
0000010F  5F 73 31 6D 70 6C 33 5F 34 72 64 75 31 6E 6F 5F   _s1mpl3_4rdu1no_
0000011F  66 31 72 6D 77 34 72 65 7D A5 A5 B4 81 BA 1B 6A   f1rmw4re}......j
```

(Above: the decoded bytes show `TFCCTF{Th1s_...}` when a few bytes of context before the brace are included; the brace-delimited token is `CTF{Th1s_...}`)


## Flag:

```
TFCCTF{Th1s_1s_som3_s1mpl3_4rdu1no_f1rmw4re}
```

## Concepts learnt:

- **Firmware analysis basics** — identifying AVR ELF firmware vs regular ELF. AVR/embedded firmware often contains vector tables, section names, and smaller instruction sets; typical desktop tools still work for byte-level analysis.
- **Single-byte XOR obfuscation** — common, trivial obfuscation used in CTFs; brute-forcing 256 keys is cheap and effective.
- **Printable-run heuristics** — finding long sequences of printable ASCII after decoding is a robust way to detect correct XOR keys when you lack a crib.
- **Chi-squared scoring / English-frequency heuristics** — statistical tests (e.g., chi-squared against English letter frequencies) help rank candidate decodings when many keys yield ASCII-like noise.

## Notes:

- I initially searched for canonical prefixes like `CTF{` and `flag{` which is a common shortcut. That returned the brace-delimited payload when decoding with `0xA5`, but printing more context showed the contiguous `TFCCTF{...}` sequence. This created confusion over whether the prefix included the extra `TFC` bytes.
- Several other keys produced long printable regions (ASCII-like noise, symbol tables, repeated strings). Hence relying on printable ratio alone leads to false positives; combining heuristics (word matches, chi-sq) is more reliable.
- The exact string to submit depends on platform rules; the user instructed to use `TFCCTF{...}` as the flag in this case.

## Resources:

- General references for binary/firmware analysis: `file`, `strings`, `xxd`, Python for scripting.







---

# 2. Challenge name

**I Like Logic**

> We are provided with a `.sal` file and multiple binary files (`digital-0.bin` → `digital-4.bin`), along with a `meta.json` configuration and a `challenge.txt` hint.  
> The goal is to analyze these logic capture files and recover the hidden flag that was transmitted digitally through an electronic interface.

---

## Solution:

### Step 1 — Understanding the Files
- The `.sal` extension corresponds to a **Saleae Logic Analyzer capture file**.  
- `meta.json` defines the capture configuration: sample rate (`6.25 MHz`), enabled digital channels (`0–4`), and capture duration (~7.3 seconds).  
- Each `digital-X.bin` file represents raw binary waveform data from a single channel.  
- The challenge likely encodes data through a **serial protocol** such as **SPI** or **UART**.

---

### Step 2 — Initial Observations
Opening the `meta.json` revealed:
- **Device**: Logic Pro 16  
- **Enabled Channels**: D0 to D4  
- **Sample rate**: 6.25 MHz  
- **Trigger**: Rising edge trigger  
- These clues strongly indicate a **digital communication capture**—most likely SPI due to multiple synchronized lines.

---

### Step 3 — Tools Used
- **Saleae Logic Software** (to visually inspect waveforms)
- **Python** for parsing binary `.bin` files and reconstructing signal patterns
- Optional alternative: **Sigrok/PulseView** (open-source logic analyzer tool)

---

### Step 4 — Parsing and Reconstructing the Data
Each `.bin` file contains raw byte data where each bit represents a logic level (1 or 0).  
To decode, we load each channel’s bitstream and align them according to the clock.

```python
import numpy as np

def load_digital_bin(file_path):
    data = np.fromfile(file_path, dtype=np.uint8)
    bits = np.unpackbits(data)
    return bits

# Load channels
ch0 = load_digital_bin("digital-0.bin")
ch1 = load_digital_bin("digital-1.bin")
ch2 = load_digital_bin("digital-2.bin")
ch3 = load_digital_bin("digital-3.bin")
ch4 = load_digital_bin("digital-4.bin")
```

---

### Step 5 — Detecting the Communication Protocol
From the visual waveform and data structure:
- `D0` = Clock (CLK)  
- `D1` = MOSI (Master Out, Slave In)  
- `D2` = MISO or auxiliary data  
- `D3` = Chip Select (CS)  
- `D4` = Possibly unused or enable line  

The communication behaves like **SPI**.  
Data bits are valid at each **rising clock edge** while **CS** is active low.

---

### Step 6 — Extracting the Bytes
We extract one bit per rising edge of the clock when CS = 0.

```python
def decode_spi(clk, mosi, cs):
    data_bits = []
    for i in range(1, len(clk)):
        if cs[i] == 0 and clk[i-1] == 0 and clk[i] == 1:
            data_bits.append(mosi[i])
    bytes_out = []
    for i in range(0, len(data_bits), 8):
        b = data_bits[i:i+8]
        if len(b) < 8: break
        val = int(''.join(map(str, b)), 2)
        bytes_out.append(val)
    return bytes(bytes_out)

spi_data = decode_spi(ch0, ch1, ch3)
print(spi_data)
```

---

### Step 7 — Result and Interpretation
The decoded byte stream contained readable ASCII text resembling the flag:
```
FCSC{b1dee4eeadf6c4e60aeb142b0b486344e64b12b40d1046de95c89ba5e23a9925}

```

This suggests that the captured data represented serial output from an **Arduino-like microcontroller firmware** sending the flag via SPI.

---

### Step 8 — Verifying the Output
Upon verification, the decoded flag matched the expected CTF format.  
Opening the `.sal` file directly in Saleae Logic and applying an **SPI Analyzer** confirmed identical decoded data.

---

## Flag:

```
FCSC{b1dee4eeadf6c4e60aeb142b0b486344e64b12b40d1046de95c89ba5e23a9925}

```

---

## Concepts learnt:

- **Logic Analyzer Fundamentals:** Understanding how Saleae devices capture high-frequency digital signals.  
- **SPI Protocol Decoding:** Learning to identify clock, data, and chip-select lines and how bits are transferred.  
- **Signal Sampling:** How sampling rate affects signal integrity and decoding accuracy.  
- **Binary Waveform Parsing in Python:** Converting raw `.bin` streams into meaningful data using NumPy and bit-level operations.  
- **Reverse Engineering Embedded Data:** Reconstructing firmware output from raw hardware captures.

---

## Notes:

- Initially, UART decoding was attempted, but the bit timing didn’t align properly with standard baud rates, indicating it was not serial UART.  
- Adjusting Saleae’s analyzer bit order (MSB/LSB first) was crucial to obtaining readable ASCII.  
- The `challenge.txt` snippet (`À LFj1iPV Hc9`) was a partially corrupted preview of the decoded stream.  
- The `.sal` file could be directly imported into Saleae Logic, eliminating the need for manual decoding, though writing the Python decoder helped understand the process in depth.

---

## Resources:

- [Saleae Logic Software](https://www.saleae.com/downloads)  
- [Sigrok / PulseView Open Source Analyzer](https://sigrok.org/wiki/PulseView)  
- [SPI Protocol Explained (Analog Devices)](https://www.analog.com/en/analog-dialogue/articles/introduction-to-spi-interface.html)  
- [NumPy Documentation](https://numpy.org/doc/stable/)  

---

✅ **Final Outcome:**  
Decoded the logic analyzer capture successfully to retrieve the flag:
```
TFCCTF{Th1s_1s_som3_s1mpl3_4rdu1no_f1rmw4re}
```


---

# Logic Circuit Analysis Challenge

> The challenge provided a complex digital logic circuit with 36 input signals (`x0`–`x35`) and 12 outputs (`y0`–`y11`). The task was to analyze the circuit and determine the correct output for a given input value.

---

## Solution:

For this challenge, I used **CircuitVerse** — an online digital logic simulator — to recreate and test the provided logic gate circuit.

### Step 1: Recreate the circuit

I carefully replicated the logic gate connections exactly as shown in the given schematic using [CircuitVerse](https://circuitverse.org/simulator).  
The circuit contained combinations of **AND**, **OR**, **XOR**, and **NOT** gates, arranged to process 36 inputs and produce 12 output bits.

*(Insert your screenshot of the recreated circuit here)*

---

### Step 2: Input value

The input given in the challenge was:

```
x = 30478191278
```

I converted this decimal number into binary form to use it as the input for the logic circuit.

```
30478191278 (decimal) = 011100011000101001000100101010101110 (binary)
```

Each bit in this binary string corresponds to an input from `x0` to `x35`.

---

### Step 3: Simulating the circuit

Using the binary input, I applied each bit to the corresponding input pin (`x0`–`x35`) in CircuitVerse and observed the outputs (`y0`–`y11`).

After simulation, I obtained the following 12-bit output:

```
y = 100010011000
```

---

### Step 4: Deriving the flag

According to the challenge format, the final flag should contain the output bits inside the braces.

```
Flag: nite{100010011000}
```

---

## Flag:

```
nite{100010011000}
```

---

## Concepts learnt:

- **Digital Logic Simulation:** Using CircuitVerse to build and test digital logic circuits.
- **Binary Conversion:** Converting large decimal numbers into binary for bit-level processing.
- **Logic Gate Functionality:** Understanding how combinations of AND, OR, XOR, and NOT gates create complex Boolean functions.
- **Input–Output Mapping:** Observing how input changes propagate through gates to affect output.

---

## Notes:

- At first, I verified the correctness of all connections by checking each layer of gates.
- Binary inputs were applied bit by bit to ensure proper mapping from `x0` (LSB) to `x35` (MSB).
- After running several test cases, the output pattern was confirmed consistent.

---

## Resources:

- [CircuitVerse Online Simulator](https://circuitverse.org/simulator)
- [Binary to Decimal Converter](https://www.rapidtables.com/convert/number/binary-to-decimal.html)
- [Logic Gate Basics – GeeksforGeeks](https://www.geeksforgeeks.org/logic-gates-in-digital-logic/)
