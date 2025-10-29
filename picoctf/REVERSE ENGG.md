# 1. VaultDoor3

> **Description**  
> This vault uses for-loops and byte/char arrays. The source code for this vault is here: `VaultDoor3.java`  
> (Author: Mark E. Haase)  
> The program reads a `picoCTF{...}` string, strips the `picoCTF{`/`}` wrapper, runs a sequence of writes into a 32-char `buffer` using several for-loops, builds a `String` from `buffer` and compares it against a target string. We must find the input that makes the comparison true.

---

## Solution:

**High level idea:**  
Reverse the transformations performed by `checkPassword`. The method writes `buffer[i] = password.charAt(f(i))` for a piecewise-defined index function `f(i)` (determined by the four for-loops). We construct the mapping `buffer_index -> password_index`, invert it, and then read the target `s` (the final string the code compares to) to reconstruct the original `password` (the string inside the `picoCTF{}` wrapper). Finally, wrap it as `picoCTF{...}`.

### Step-by-step thought process & reasoning

1. Read the Java `checkPassword` logic carefully and translate each loop into a mapping from `buffer` index to `password` index:

   - Loop 1: `for (i=0; i<8; i++) buffer[i] = password.charAt(i);`  
     ⇒ `buffer[0..7] = password[0..7]` (so `f(i)=i` for `0<=i<=7`)

   - Loop 2: `for (; i<16; i++) buffer[i] = password.charAt(23-i);`  
     ⇒ for `i` in `8..15`, `f(i)=23-i` (reverses a slice)

   - Loop 3: `for (; i<32; i+=2) buffer[i] = password.charAt(46-i);`  
     ⇒ for even `i` starting at 16 (`i=16,18,20,...,30`), `f(i)=46-i`

   - Loop 4: `for (i=31; i>=17; i-=2) buffer[i] = password.charAt(i);`  
     ⇒ for odd `i` from 31 down to 17 (`i=31,29,...,17`), `f(i)=i` (these writes overwrite certain `buffer` indices written earlier or fill the odd high indices)

2. Build the `buffer_index -> password_index` mapping explicitly (we show it in code below). That mapping is what the Java code uses to assemble the `String s` from `password`.

3. Given the final string the Java code compares against (the `s` literal in the Java program), set `password[p_index] = s[buffer_index]` for each buffer index and produce the required `password`. The result is the 32-character string that must be inside `picoCTF{...}`.

4. Verify by simulating the same write operations and confirm the simulated `s` equals the expected target `s`.

---

### Code used (Python) — reverse and verify

```python
# target s (the string the Java code compares to)
s_target = "jU5t_a_sna_3lpm18g947_u_4_m9r54f"

# build mapping buffer_index -> password_index (reflecting the Java loops)
buffer_to_password_index = {}
# loop1: i = 0..7
for i in range(0,8):
    buffer_to_password_index[i] = i
# loop2: i = 8..15
for i in range(8,16):
    buffer_to_password_index[i] = 23 - i
# loop3: i = 16..30 step 2 (even positions)
for i in range(16,32,2):
    buffer_to_password_index[i] = 46 - i
# loop4: i = 31 down to 17 step -2 (odd positions >=17)
for i in range(31,16,-2):
    buffer_to_password_index[i] = i

# invert mapping to build password of length 32
password_chars = ['?'] * 32
for b in range(32):
    p_index = buffer_to_password_index[b]
    password_chars[p_index] = s_target[b]

password = ''.join(password_chars)
print("password (32 chars):", password)
print("Flag: picoCTF{{{}}}".format(password))

# verify by simulating the Java writes to buffer
buffer = [None] * 32
for i in range(0,8):
    buffer[i] = password[i]
for i in range(8,16):
    buffer[i] = password[23-i]
for i in range(16,32,2):
    buffer[i] = password[46-i]
for i in range(31,16,-2):
    buffer[i] = password[i]
s_sim = ''.join(buffer)
print("Simulated s:", s_sim)
print("Matches target?", s_sim == s_target)
```

### Terminal / script output

```
password (32 chars): jU5t_a_s1mpl3_an4gr4m_4_u_79958f
Flag: picoCTF{jU5t_a_s1mpl3_an4gr4m_4_u_79958f}
Simulated s: jU5t_a_sna_3lpm18g947_u_4_m9r54f
Matches target? True
```

> **Conclusion:** the input that must be supplied to the Java program as `picoCTF{...}` is:
>
> ```
> picoCTF{jU5t_a_s1mpl3_an4gr4m_4_u_79958f}
> ```

---

## Flag:

```
picoCTF{jU5t_a_s1mpl3_an4gr4m_4_u_79958f}
```

---

## Concepts learnt:

- **Index mapping & loop reasoning** — Translating a sequence of loops that write to an array into an explicit mapping from target indices to source indices is a reliable reversal technique.
- **Reversing a deterministic transformation** — When a program transforms an input using pure indexing and no secret state, you can invert the mapping by algebraically solving index equations or by constructing a mapping programmatically.
- **Careful handling of overlapping writes** — The order of loops (particularly a later loop that overwrites earlier buffer cells) matters; always model the sequence exactly in the same order to get correct results.
- **String slicing and char arithmetic in Java/Python** — Understanding `charAt`, substring extraction and 0-based indexing differences is essential when porting logic between languages.
- **Verification by simulation** — After reconstructing a candidate input, re-run the same transformations to confirm they produce the expected target string before claiming the final flag.

---

## Notes:

- **Common pitfalls / mistakes**
  - Misreading the final literal `s` in the Java code (different versions of the challenge use slightly different target strings; be sure to use the exact string present in your copy).
  - Failing to account for the *direction* and *order* of writes. Because the last loop writes high odd indices from 31 down to 17, you must ensure your mapping respects that overwrite behavior.
  - Assuming symmetry where there is none — each loop had different formulas (`i`, `23-i`, `46-i`) and targets (even/odd index patterns).

- **Alternate approaches**
  - Brute force the input (impractical here: 32 chars).
  - Symbolic/constraint solver (e.g., z3) — overkill for this deterministic index mapping but possible.
  - Manual algebra to compute each password index — doable but error-prone without programmatic verification.

---

## Resources:

- Challenge source (present in problem statement): `VaultDoor3.java`  

---


***

# 2.ARMassembly-1 CTF Challenge

> For what argument does this program print `win` with variables 83, 0 and 3? File: chall_1.S Flag format: picoCTF{XXXXXXXX} -> (hex, lowercase, no 0x, and 32 bits. ex. 5614267 would be picoCTF{0055aabb})

## Solution:

### Step 1: Understanding the Challenge

This is an ARM assembly reverse engineering challenge where we need to analyze the assembly code to find the correct input that makes the program print "You win!". The challenge provides three hardcoded values (83, 0, 3) and we need to determine what user input will satisfy the win condition.

### Step 2: Analyzing the Main Function

First, let's look at the main function structure:

```assembly
main:
    stp x29, x30, [sp, -48]!
    add x29, sp, 0
    str w0, [x29, 28]
    str x1, [x29, 16]
    ldr x0, [x29, 16]
    add x0, x0, 8
    ldr x0, [x0]
    bl atoi                    # Convert string input to integer
    str w0, [x29, 44]
    ldr w0, [x29, 44]
    bl func                    # Call the main logic function
    cmp w0, 0                  # Compare result with 0
    bne .L4                    # Branch if NOT equal (lose)
    adrp x0, .LC0
    add x0, x0, :lo12:.LC0
    bl puts                    # Print "You win!"
    b .L6
.L4:
    adrp x0, .LC1
    add x0, x0, :lo12:.LC1
    bl puts                    # Print lose message
.L6:
    nop
    ldp x29, x30, [sp], 48
    ret
```

**Key Observations:**
- The program uses `atoi` to convert our string input to an integer
- It calls a function `func` with our input
- It compares the result with 0
- If the result equals 0, we win!

### Step 3: Analyzing the func Function

Now let's examine the core logic in the `func` function:

```assembly
func:
    sub sp, sp, #32
    str w0, [sp, 12]           # Store user input at stack+12
    mov w0, 83
    str w0, [sp, 16]           # stack+16 = 83
    mov w0, 0
    str w0, [sp, 20]           # stack+20 = 0
    mov w0, 3
    str w0, [sp, 24]           # stack+24 = 3
    ldr w0, [sp, 20]           # w0 = 0
    ldr w1, [sp, 16]           # w1 = 83
    lsl w0, w1, w0             # w0 = 83 << 0
    str w0, [sp, 28]           # stack+28 = result
    ldr w1, [sp, 28]           # w1 = result
    ldr w0, [sp, 24]           # w0 = 3
    sdiv w0, w1, w0            # w0 = result / 3
    str w0, [sp, 28]           # stack+28 = final result
    ldr w1, [sp, 28]           # w1 = final result
    ldr w0, [sp, 12]           # w0 = user input (x)
    sub w0, w1, w0             # w0 = final_result - x
    str w0, [sp, 28]
    ldr w0, [sp, 28]
    add sp, sp, 32
    ret
```

### Step 4: Variable Mapping

| Stack Location | Value | Description |
|---------------|-------|-------------|
| stack+12 | x | User Input (unknown) |
| stack+16 | 83 | First parameter |
| stack+20 | 0 | Second parameter |
| stack+24 | 3 | Third parameter |
| stack+28 | varies | Working result |

### Step 5: Tracing the Execution

**Operation 1: Left Shift (LSL)**

```assembly
ldr w0, [sp, 20]    # w0 = 0
ldr w1, [sp, 16]    # w1 = 83
lsl w0, w1, w0      # w0 = 83 << 0
```

```python
>>> 83 << 0
83
```

So `stack+28 = 83`

**Operation 2: Signed Division (SDIV)**

```assembly
ldr w1, [sp, 28]    # w1 = 83
ldr w0, [sp, 24]    # w0 = 3
sdiv w0, w1, w0     # w0 = 83 // 3
```

```python
>>> 83 // 3
27
```

So `stack+28 = 27`

**Operation 3: Subtraction**

```assembly
ldr w1, [sp, 28]    # w1 = 27
ldr w0, [sp, 12]    # w0 = x (user input)
sub w0, w1, w0      # w0 = 27 - x
```

The function returns `27 - x`

### Step 6: Finding the Win Condition

Back in main:

```
cmp w0, 0
bne .L4
```

So we win when:

```
27 - x = 0
x = 27
```

### Step 7: Converting to Flag Format

```python
>>> format(27, '08x')
'0000001b'
```

## Flag:

```
picoCTF{0000001b}
```

## Concepts learnt:

- **ARM Assembly Language**
- **Stack Operations**
- **Registers and Calling Convention**
- **LSL (Logical Shift Left)**
- **SDIV (Signed Division)**
- **atoi Function**
- **Branch Instructions**
- **Comparison Logic**

## Notes:

- **Key Insight**: We must find input such that function returns 0.
- **Formula:** `(param1 << param2) / param3 = input`
- **Different Example:** `(79 << 7) / 3 = 3370 → picoCTF{00000d2a}`
- **Correct Flag for our case:** `(83 << 0)/3 = 27 → picoCTF{0000001b}`

## Resources:

- [ARM Assembly Language Documentation](https://developer.arm.com/documentation/dui0473/m/arm-and-thumb-instructions)
- [ARM Instruction Set Quick Reference](https://www.keil.com/support/man/docs/armasm/armasm_dom1361289850039.htm)
- [PicoCTF Platform](https://picoctf.org/)
- [ARM Architecture Registers](https://developer.arm.com/documentation/102374/0101/Registers-in-AArch64---general-purpose-registers)


***

# GDB Baby Step 1

> Can you figure out what is in the `eax` register at the end of the `main` function? Put your answer in the picoCTF flag format: `picoCTF{n}` where `n` is the contents of the `eax` register in the decimal number base. If the answer was `0x11` your flag would be `picoCTF{17}`. Disassemble this.

## Solution:

### Step 1: Understanding the Challenge

This is a reverse engineering challenge where we need to:
1. Download an executable file
2. Use GDB (GNU Debugger) to disassemble and analyze it
3. Find the value stored in the EAX register at the end of the main function
4. Convert the hexadecimal value to decimal format for the flag

The challenge provides an executable file called `debugger0_a` that we need to analyze.

### Step 2: Gathering File Information

Before we start debugging, it's important to understand what type of file we're dealing with. Using the `file` command:

```bash
$ file debugger0_a
debugger0_a: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=15a10290db2cd2ec0c123cf80b88ed7d7f5cf9ff, for GNU/Linux 3.2.0, not stripped
```

**Key Information:**
- **File Type**: ELF (Executable and Linkable Format) - Linux executable
- **Architecture**: x86-64 (64-bit)
- **Status**: Not stripped (symbols are still present, making debugging easier)

### Step 3: Opening the File in GDB

Launch GDB with the executable:

```bash
$ gdb debugger0_a
GNU gdb (Ubuntu 12.1-0ubuntu1~22.04) 12.1
Copyright (C) 2022 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Reading symbols from debugger0_a...
(No debugging symbols found in debugger0_a)
(gdb)
```

### Step 4: Listing Functions

To see what functions are available in the binary:

```bash
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x0000000000001000  _init
0x0000000000001030  __cxa_finalize@plt
0x0000000000001040  _start
0x0000000000001070  deregister_tm_clones
0x00000000000010a0  register_tm_clones
0x00000000000010e0  __do_global_dtors_aux
0x0000000000001120  frame_dummy
0x0000000000001129  main
0x0000000000001140  _fini
```

**Important Finding**: The `main` function is located at address `0x0000000000001129`

### Step 5: Setting Disassembly Syntax

GDB uses AT&T syntax by default, but Intel syntax is more commonly used and easier to read. Let's switch:

```bash
(gdb) set disassembly-flavor intel
```

**Difference between syntaxes:**
- **AT&T**: `mov %eax, %ebx` (source first, destination second)
- **Intel**: `mov ebx, eax` (destination first, source second)

### Step 6: Disassembling the Main Function

Now let's disassemble the main function to see the assembly instructions:

```bash
(gdb) disassemble main
Dump of assembler code for function main:
   0x0000000000001129 <+0>:     endbr64 
   0x000000000000112d <+4>:     push   rbp
   0x000000000000112e <+5>:     mov    rbp,rsp
   0x0000000000001131 <+8>:     mov    DWORD PTR [rbp-0x4],edi
   0x0000000000001134 <+11>:    mov    QWORD PTR [rbp-0x10],rsi
   0x0000000000001138 <+15>:    mov    eax,0x86342
   0x000000000000113d <+20>:    pop    rbp
   0x000000000000113e <+21>:    ret    
End of assembler dump.
```

### Step 7: Analyzing the Assembly Code

Let's break down what each instruction does:

```assembly
0x0000000000001129 <+0>:     endbr64
```
- **endbr64**: End Branch 64-bit - a security feature for Control-flow Enforcement Technology (CET)

```assembly
0x000000000000112d <+4>:     push   rbp
0x000000000000112e <+5>:     mov    rbp,rsp
```
- **Function Prologue**: Sets up the stack frame
- Saves the old base pointer and sets up a new one

```assembly
0x0000000000001131 <+8>:     mov    DWORD PTR [rbp-0x4],edi
0x0000000000001134 <+11>:    mov    QWORD PTR [rbp-0x10],rsi
```
- Stores function parameters on the stack
- `edi` contains argc (argument count)
- `rsi` contains argv (argument vector)

```assembly
0x0000000000001138 <+15>:    mov    eax,0x86342
```
- **THIS IS THE KEY INSTRUCTION!**
- Moves the hexadecimal value `0x86342` into the EAX register
- This happens at the end of the main function, right before returning

```assembly
0x000000000000113d <+20>:    pop    rbp
0x000000000000113e <+21>:    ret
```
- **Function Epilogue**: Cleans up the stack frame and returns
- The value in EAX is the return value of the function

### Step 8: Converting Hexadecimal to Decimal

The value in EAX is `0x86342` (hexadecimal). We need to convert this to decimal.

**Method 1: Using GDB's print command**

```bash
(gdb) print 0x86342
$1 = 549698
```

**Method 2: Manual Conversion**

```
0x86342 = (8 × 16^4) + (6 × 16^3) + (3 × 16^2) + (4 × 16^1) + (2 × 16^0)
        = (8 × 65536) + (6 × 4096) + (3 × 256) + (4 × 16) + (2 × 1)
        = 524288 + 24576 + 768 + 64 + 2
        = 549698
```

**Method 3: Using Python**

```python
>>> int(0x86342)
549698
>>> hex(549698)
'0x86342'
```

### Step 9: Verification (Optional)

We can also run the program and inspect the EAX register at runtime:

```bash
(gdb) break main
Breakpoint 1 at 0x1131

(gdb) run
Starting program: /path/to/debugger0_a 
Breakpoint 1, 0x0000555555555131 in main ()

(gdb) disassemble
   0x0000555555555129 <+0>:     endbr64 
   0x000055555555512d <+4>:     push   rbp
   0x000055555555512e <+5>:     mov    rbp,rsp
=> 0x0000555555555131 <+8>:     mov    DWORD PTR [rbp-0x4],edi
   0x0000555555555134 <+11>:    mov    QWORD PTR [rbp-0x10],rsi
   0x0000555555555138 <+15>:    mov    eax,0x86342
   0x000055555555513d <+20>:    pop    rbp
   0x000055555555513e <+21>:    ret

(gdb) break *0x000055555555513d
Breakpoint 2 at 0x55555555513d

(gdb) continue
Continuing.
Breakpoint 2, 0x000055555555513d in main ()

(gdb) info registers eax
eax            0x86342             549698
```

## Flag:

```
picoCTF{549698}
```

## Concepts learnt:

- **GDB (GNU Debugger)**: A powerful debugging tool for analyzing and debugging programs. It allows you to inspect memory, registers, set breakpoints, and step through code execution.

- **ELF Format**: Executable and Linkable Format is the standard binary format for executables on Linux systems. It contains headers, sections, and segments that define how the program should be loaded and executed.

- **x86-64 Architecture**: The 64-bit extension of the x86 instruction set. Uses 64-bit registers (rax, rbx, etc.) but can also use 32-bit versions (eax, ebx, etc.).

- **EAX Register**: A 32-bit general-purpose register in x86 architecture. It's commonly used for:
  - Return values from functions
  - Arithmetic operations
  - Function call results
  
- **Assembly Syntax Flavors**:
  - **AT&T Syntax**: Used by GDB by default, prefixes registers with %, source-destination order
  - **Intel Syntax**: More intuitive, destination-source order, no register prefixes

- **Function Prologue and Epilogue**:
  - **Prologue**: `push rbp; mov rbp, rsp` - Sets up stack frame
  - **Epilogue**: `pop rbp; ret` - Cleans up and returns

- **Hexadecimal to Decimal Conversion**: Understanding number base conversions is crucial for reverse engineering. Hex values are often used in assembly because they map cleanly to binary.

- **Disassembly**: The process of converting machine code back into human-readable assembly language instructions.

- **Return Values in x86-64**: By convention, integer return values are stored in the RAX/EAX register. This is part of the calling convention.

## Notes:

- **Why EAX and not RAX?**: Even though this is a 64-bit binary, the instruction uses `mov eax, 0x86342`. When you write to a 32-bit register (EAX), the upper 32 bits of the 64-bit register (RAX) are automatically zeroed. This is a x86-64 architecture feature.

- **Static vs Dynamic Analysis**: 
  - In this challenge, we used **static analysis** - examining the code without running it
  - We could also use **dynamic analysis** - running the program and inspecting registers at runtime
  - For this simple case, static analysis was sufficient since the value is hardcoded

- **The 'not stripped' advantage**: The file being "not stripped" means debugging symbols are present, making it easier to identify functions by name. Stripped binaries only show addresses.

- **Why check EAX at the end?**: The challenge specifically asks for the value "at the end of the main function" because:
  - EAX might change multiple times during execution
  - The final value is what gets returned from main()
  - In C, `return 549698;` would compile to `mov eax, 0x86342`

- **Alternative Tools**: While we used GDB, other tools for reverse engineering include:
  - **objdump**: `objdump -d debugger0_a -M intel`
  - **radare2**: More advanced reverse engineering framework
  - **IDA Pro / Ghidra**: GUI-based disassemblers
  - **Binary Ninja**: Modern reverse engineering platform

- **Common Beginner Mistakes**:
  - Forgetting to convert hex to decimal
  - Looking at the wrong register (e.g., RAX vs EAX)
  - Not setting Intel syntax and getting confused by AT&T syntax
  - Checking register value at the wrong point in execution


***
