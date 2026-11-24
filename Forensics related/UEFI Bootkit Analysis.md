#Forensics #Disk-FOR #
# **UEFI Bootkit Analysis: Detecting Hidden Data in** `bootmgr.efi` **Using HxD**

This scenario combines several important cybersecurity concepts:

1. UEFI boot architecture.
2. Windows bootloader internals.
3. PE (Portable Executable) file structure.
4. Hexadecimal analysis.
5. Digital signatures and Secure Boot.
6. Bootkit persistence and forensic investigation.

The interesting part of this investigation is that the attacker may not have replaced the entire bootloader. Instead, they may have **modified an existing legitimate bootloader by embedding malicious or encoded data inside an area that normally contains unused or non-executable bytes.**

Let's approach this as a forensic investigation.

# **1. First, understand what we're investigating**

The organization detected a bootkit on a Windows server.

A bootkit is a type of malware designed to compromise the boot process, allowing malicious code to execute very early, potentially before the operating system and its security controls are fully initialized.

Why is this dangerous?

Because traditional security products usually operate inside the operating system. A bootkit may execute before those products start.

For example:

```
Normal Windows boot:

UEFI
 |
 v
Windows Boot Manager
 |
 v
Windows Loader
 |
 v
Windows Kernel
 |
 v
EDR / Antivirus
 |
 v
User applications
```

A compromised boot process could look like this:

```
Compromised boot:

UEFI
 |
 v
Windows Boot Manager (Modified)
 |
 v
Malicious bootkit component
 |
 v
Windows Loader
 |
 v
Windows Kernel
 |
 v
EDR / Antivirus
 |
 v
User applications
```

The malicious component may execute before the security software initializes.

It could potentially:

- Hide malicious processes.
    
- Manipulate kernel structures.
    
- Interfere with security products.
    
- Load additional malicious components.
    
- Establish persistence across reboots.
    

These are potential capabilities, not proof that this particular bootkit performed all of them.

## **What is the investigator's task?**

You have been given:

```
C:\Analysis\bootmgr.efi
```

Your objective is to determine whether this file has been modified and whether suspicious data has been embedded in its initial unused space.

Notice that we're analyzing a file extracted for investigation, not necessarily accessing the original EFI partition directly.

# **2. Understanding the relationship between UEFI, GPT, and bootmgr.efi**

Before opening HxD, let's understand where this file fits into the boot architecture.

Your laptop uses GPT and UEFI, so let's use that as an example.

The EFI System Partition (ESP) is a special partition on a GPT disk. It normally uses FAT32.

Inside it, Windows typically stores its boot files:

```
EFI System Partition (FAT32)
|
+-- EFI
    |
    +-- Microsoft
        |
        +-- Boot
            |
            +-- bootmgfw.efi
            |
            +-- BCD
            |
            +-- ...
```

There is also a standard fallback bootloader path on x64 UEFI systems:

```
\EFI\BOOT\BOOTX64.EFI
```

These files have different roles and locations.

|File|Purpose|
|---|---|
|`bootmgfw.efi`|Windows Boot Manager|
|`bootx64.efi`|Default x64 UEFI fallback boot filename|
|`BCD`|Boot Configuration Data|
|`winload.efi`|Windows OS Loader|

**Important correction:** The normal Windows Boot Manager filename is `bootmgfw.efi`, not `bootmgr.efi`. Your scenario uses `bootmgr.efi` as the supplied sample filename. It may be a renamed or lab-provided copy, so don't assume its original identity from its filename alone.

### **How does UEFI find the bootloader?**

UEFI maintains boot entries in motherboard NVRAM.

For example:

```
BootOrder = 0001, 0002

Boot0001:
    Windows Boot Manager

    Device:
        EFI System Partition

    Path:
        \EFI\Microsoft\Boot\bootmgfw.efi
```

The firmware uses this information to locate the EFI executable.

It then loads the executable into memory and transfers execution to it.

This is fundamentally different from traditional BIOS booting, where the firmware executes bootstrap code from LBA 0.

# **3. What is a bootkit, and how can it modify an EFI file?**

A bootkit is malware that targets the boot process.

In a UEFI environment, an attacker may attempt to compromise the boot chain through several mechanisms:

|Technique|Explanation|
|---|---|
|EFI file modification|Alters an existing EFI executable|
|Malicious EFI application|Introduces another executable into the boot chain|
|Boot entry manipulation|Changes which EFI application firmware launches|
|Firmware compromise|Modifies firmware components|
|Vulnerable signed bootloader|Abuses a legitimately signed but vulnerable component|

In your scenario, the suspected technique is EFI file modification.

Imagine the original bootloader:

```
bootmgr.efi

+----------------------------------+
| Legitimate PE Header             |
+----------------------------------+
| Legitimate Executable Code       |
+----------------------------------+
| Legitimate Data                  |
+----------------------------------+
```

The attacker modifies it:

```
bootmgr.efi

+----------------------------------+
| Legitimate PE Header             |
+----------------------------------+
| Hidden Encoded String            | <-- Suspicious
+----------------------------------+
| Legitimate Executable Code       |
+----------------------------------+
| Legitimate Data                  |
+----------------------------------+
```

The hidden string might contain:

- An encrypted configuration.
    
- A URL or IP address.
    
- A payload identifier.
    
- A command-and-control address.
    
- A decryption key.
    
- Instructions for another component.
    

For example, an attacker might embed:

```
68747470733A2F2F6576696C2E6578616D706C65
```

This is hexadecimal-encoded ASCII.

When decoded:

```
https://evil.example
```

This is only an illustrative example. Finding an encoded string does not automatically prove that it is malicious.

# **4. Understanding the PE file structure**

[[PE (Portable Executable) format]] *last section*

# **5. What exactly is the "initial unused space"?**

Your scenario specifically says:

> The attacker embedded an encoded string in the initial unused space of the bootloader.

This is a very important clue.

It suggests that you should investigate the bytes near the beginning of the PE file, particularly the region between the DOS header and the PE signature.

But don't assume that every byte before the PE signature is unused.

There are several different concepts:

|Area|Meaning|
|---|---|
|DOS header|Required PE header information|
|DOS stub|Compatibility code|
|DOS stub padding|Potentially unused bytes|
|PE header|Executable metadata|
|Section alignment padding|Space added to satisfy alignment|
|Section slack|Unused space inside a section's allocated raw data|
|Overlay|Data appended after the normal PE image sections|

The important forensic task is to distinguish legitimate structures from unexplained data.

### **Example: Normal vs suspicious bytes**

Imagine the original file has:

```
00000040  54 68 69 73 20 70 72 6F
00000048  67 72 61 6D 20 63 61 6E
00000050  6E 6F 74 20 62 65 20 72
00000058  75 6E 20 69 6E 20 44 4F
00000060  53 20 6D 6F 64 65 2E 0D
00000068  0A 24 00 00 00 00 00 00
00000070  00 00 00 00 00 00 00 00
00000078  00 00 00 00 00 00 00 00
00000080  50 45 00 00
```

Here, the bytes between `0x70` and `0x7F` are zero padding.

Now imagine the suspicious file contains:

```
00000070  68 74 74 70 73 3A 2F 2F
00000078  65 76 69 6C 2E 65 78 61
00000080  50 45 00 00
```

Instead of zero padding, we have:

```
https://evil.exa
```

This is potentially suspicious because:

- It occupies a region that may otherwise contain padding.
- It contains a readable URL.
- It is unrelated to the normal DOS stub message.

However, one string alone is not sufficient evidence of malicious activity. We need to determine whether the bytes belong to legitimate file content, whether they are referenced by the executable, and whether the file differs from a trusted version.

# **6. How does Secure Boot detect a modified bootloader?**

This is where the scenario connects to cryptography.

UEFI Secure Boot is designed to ensure that only EFI applications trusted under the platform's Secure Boot policy are allowed to execute.

It uses cryptographic signatures and trusted certificates.

The simplified process:

```
             UEFI FIRMWARE
                   |
                   v
          Load bootmgfw.efi
                   |
                   v
          Calculate image hash
                   |
                   v
          Verify image signature
                   |
                   v
          Check Secure Boot policy
                   |
             +-----+-----+
             |           |
             v           v
          Trusted     Rejected
             |           |
             v           v
        Execute EFI    Block boot
        application
```

UEFI maintains important Secure Boot databases:

|Database|Purpose|
|---|---|
|PK|Platform Key; establishes platform ownership|
|KEK|Key Exchange Keys; authorize updates to signature databases|
|db|Allowed signatures and hashes|
|dbx|Revoked signatures and hashes|

### **Example: An attacker modifies bootmgfw.efi**

Suppose the original bootloader is digitally signed.

The attacker inserts:

```
https://evil.example
```

into its DOS stub padding.

Even though the executable instructions might remain unchanged, the file's Authenticode image hash will normally change.

If the modified image no longer has a valid trusted signature, Secure Boot should reject it.

**Important correction:** Secure Boot does not simply check whether a file has a digital signature. It checks whether the image is trusted according to its signature and revocation policy.

There are also ways attackers can get around this protection, including:

- Exploiting vulnerabilities in trusted, signed bootloaders.
    
- Using compromised signing keys.
    
- Abusing misconfigured Secure Boot trust databases.
    
- Disabling Secure Boot.
    
- Compromising firmware or an earlier trusted component.
    

Also, Secure Boot is not a general-purpose integrity monitor for every byte of every file after Windows has started.

A particularly important distinction for your investigation:

**Finding an embedded string in a signed bootloader does not automatically prove Secure Boot was disabled.**

You need to investigate the signature, the trust chain, the revocation status, and the actual boot environment.

# **7. Practical investigation using HxD**

Now let's perform the investigation described in your scenario.

Investigation workflow

Target:

```
C:\Analysis\bootmgr.efi
```

## **Step 1: Open the file in HxD**

HxD is a hex editor that lets you inspect and modify raw file bytes.

Open HxD:

1. Launch HxD.
    
2. Select File → Open.
    
3. Navigate to:
    

```
C:\Analysis\bootmgr.efi
```

4. Open the file.

You'll see three main areas:

[Hexadecimal notation | Microsoft Longhorn](https://images.openai.com/static-rsc-4/iBLW91P3_cpiyWPghw5Gx6pE1XLI3AsSIGLDD6bbTUjU5tA7Qxux4IO8_gd9BGKBoIvq-jXlSdDBWkVJ021Lzb8uBz_90DfjBJ7dbpQiNJHJtcKkkkzMB9EESq0z1NTRD06TDKCkUqmjbgaf5XKl5CMGa8yobILzB92Rq1VMKtk?purpose=inline)

[longhorn.ms](https://longhorn.ms/hexadecimal-system/?utm_source=chatgpt.com)

|Area|Meaning|
|---|---|
|Offset column|File position in hexadecimal|
|Hexadecimal column|Raw byte values|
|Text column|ASCII representation of bytes|

For example:

```
Offset       Hexadecimal                  ASCII
-------------------------------------------------
00000000     4D 5A 90 00 03 00 00 00      MZ......
00000008     04 00 00 00 FF FF 00 00      ........
00000010     B8 00 00 00 00 00 00 00      ........
```

The first two bytes:

```
4D 5A
```

Tell us that this file begins with the expected DOS/PE signature.

## **Step 2: Find the PE header offset**

Remember:

```
e_lfanew = Offset 0x3C
```

In HxD:

1. Press `Ctrl + G`.
    
2. Enter:
    

```
3C
```

3. Inspect the next four bytes.

Example:

```
Offset 0x3C:

80 00 00 00
```

Interpret the value as little-endian:

```
0x00000080
```

This means the PE signature should be located at offset `0x80`.

Now navigate to:

```
0x80
```

You should see:

```
50 45 00 00
```

If you see this, you've located the PE signature.

## **Step 3: Examine the bytes before the PE header**

Now inspect the area between:

```
0x40 and 0x7F
```

This is where you might find:

- The DOS stub.
    
- Padding.
    
- Suspicious embedded content.
    

Look for:

1. Unexpected readable strings.
    
2. Long sequences of unusual bytes.
    
3. Encoded URLs.
    
4. Base64-like data.
    
5. Unexplained nonzero bytes in padding.
    

Example:

```
00000070  68 74 74 70 73 3A 2F 2F
00000078  65 76 69 6C 2E 65 78 61
```

ASCII:

```
https://evil.exa
```

This would be an interesting finding requiring further investigation.

## **Step 4: Decode suspicious data**

Suppose you find:

```
68 74 74 70 73 3A 2F 2F
65 76 69 6C 2E 65 78 61
6D 70 6C 65
```

First, combine the bytes:

```
68747470733A2F2F6576696C2E6578616D706C65
```

Then interpret them as hexadecimal-encoded ASCII:

```
https://evil.example
```

You can also use PowerShell to decode a hexadecimal string:

```
$hex = "68747470733A2F2F6576696C2E6578616D706C65"

$bytes = for ($i = 0; $i -lt $hex.Length; $i += 2) {
    [Convert]::ToByte($hex.Substring($i, 2), 16)
}

[Text.Encoding]::ASCII.GetString([byte[]]$bytes)
```

Output:

```
https://evil.example
```

Not every encoded string is hexadecimal. You may encounter Base64, XOR-encoded data, compressed data, or encrypted content.

# **8. Additional forensic checks you should perform**

Don't stop after discovering the string. A professional investigation needs corroborating evidence.

Here are the checks I'd perform.

### **A. Check the digital signature**

PowerShell:

```
Get-AuthenticodeSignature "C:\Analysis\bootmgr.efi" |
Format-List Status, StatusMessage, SignerCertificate
```

Possible statuses include:

|Status|Meaning|
|---|---|
|Valid|Signature verified under the applicable Windows Authenticode trust evaluation|
|NotSigned|No recognized Authenticode signature|
|HashMismatch|File content does not match its signature|
|NotTrusted|Signer isn't trusted|
|UnknownError|Verification couldn't be completed|

Note that a Windows Authenticode result is useful evidence, but it is not a complete simulation of UEFI Secure Boot policy evaluation.

### **B. Calculate the file hash**

```
Get-FileHash "C:\Analysis\bootmgr.efi" -Algorithm SHA256
```

The SHA-256 hash helps you identify the exact file and compare it against a trusted reference.

### **C. Extract readable strings**

Using Sysinternals Strings:

```
strings64.exe -n 5 C:\Analysis\bootmgr.efi
```

This can reveal:

- URLs.
    
- IP addresses.
    
- File paths.
    
- Suspicious commands.
    
- Embedded configuration strings.
    

For a PE file, remember that strings can exist in both ASCII and Unicode formats.

### **D. Compare against a trusted version**

If you can obtain the exact legitimate version of the same Windows bootloader:

1. Compare SHA-256 hashes.
    
2. Compare file sizes.
    
3. Compare PE headers.
    
4. Compare section layouts.
    
5. Compare bytes around the suspicious offset.
    
6. Check signature validity.
    

A trusted reference should match the same Windows build and bootloader version. Comparing against a different version can produce many legitimate differences.

### **E. Examine the PE structure**

You can use tools such as:

- PE-bear.
    
- Detect It Easy (DIE).
    
- PEStudio.
    
- LIEF.
    

These help you inspect PE headers, sections, entry points, signatures, and suspicious file structures.

# **9. Important distinction: File offsets vs RVAs**

Since we're investigating PE files, there's another concept worth understanding.

A PE file has two important address representations:

**File Offset:** Where the bytes physically appear inside the file.

**RVA (Relative Virtual Address):** Where something is located relative to the executable's image base when loaded into memory.

For example:

|Address type|Example|
|---|---|
|File offset|`0x200`|
|Image base|`0x140000000`|
|RVA|`0x1000`|
|Virtual address|`0x140001000`|

For an RVA inside a section, the file offset is typically calculated using:

\[ \text{File Offset} = \text{RVA} - \text{Section RVA} + \text{PointerToRawData} \]

This is important because a suspicious string might be stored at one file offset but referenced using a different virtual address.

Also, not all file offsets have corresponding mapped memory addresses. For example, overlay data may not be mapped into the executable image.

**For your scenario:** If the encoded string is located in the DOS stub padding, it may not be part of the executable's normal mapped sections. It could be stored as data for another component to locate and decode.

# **10. One critical forensic caveat: Don't modify the evidence**

When analyzing a bootkit sample:

- Preserve the original file.
    
- Calculate its SHA-256 hash before analysis.
    
- Work on a forensic copy.
    
- Don't execute the EFI file.
    
- Don't overwrite or save changes in HxD.
    
- Record the exact file offset of every suspicious finding.
    

A string in an unused area could be:

- An attacker-inserted payload.
    
- A legitimate vendor artifact.
    
- A compiler/linker artifact.
    
- A benign debugging string.
    

Context and comparison are what establish its significance.

# **11. Summary: What you should investigate in this scenario**

Here's your investigation checklist:

## **UEFI Bootkit Forensic Checklist**

0 of 11 completed

0%

Preserve the original bootmgr.efi file

Calculate its SHA-256 hash

Check the MZ signature (4D 5A)

Locate e_lfanew at offset 0x3C

Verify the PE signature (50 45 00 00)

Inspect the DOS stub and initial padding

Search for suspicious ASCII and Unicode strings

Identify and decode suspicious encoded data

Inspect the PE sections and entry point

Check the digital signature and trust status

Compare against a trusted bootloader version

Reset checklist

## **12. Test your understanding**

Before moving to the actual lab, make sure you understand these questions:

1. Why does an EFI executable start with `MZ` even though it is not a DOS executable?
    
2. What is the purpose of `e_lfanew`?
    
3. Why might an attacker embed data in DOS stub padding instead of the `.text` section?
    
4. What is the difference between a file offset and an RVA?
    
5. Why would modifying a signed EFI executable normally invalidate its signature?
    
6. Does finding a suspicious string in an EFI file prove that Secure Boot was disabled?
    
7. Why is a legitimate, signed but vulnerable bootloader still potentially dangerous?
    

**My recommendation:** Start with questions 1–3, then open the actual `bootmgr.efi` sample in HxD. Don't assume the example offsets I showed are the offsets in your sample. We need to inspect its real `e_lfanew` value and actual padding before identifying anything as malicious.