>**MBR vs GPT LBA Addressing and Hexadecimal Structure**
#Forensics #Disk-FOR 



# **1. First, understand sectors and LBAs**

A disk is logically divided into sectors.

A common logical sector size is **512 bytes**.

Each sector has a number called an LBA (Logical Block Address).

**Example: Disk sectors**

![[Pasted image 20261118112851.png]]

Each sector is 512 bytes in this example.

- LBA 0 = bytes 0–511
- LBA 1 = bytes 512–1023
- LBA 2 = bytes 1024–1535

![[Pasted image 20261118112911.png]]

# **2. How MBR handles partitions**

MBR stores its partition information in the **first sector of the disk (LBA 0)**.

Its structure:

![[Pasted image 20261118112933.png]]
![[Pasted image 20261119133430.png|388]]
- ==🟡Yellow  --> Bootloader code (Bytes 0-446)== [^1]
- ==🟢Green  --> Partitions Table    (Bytes 446-509)==[^2]
- ==🔴Red      --> MBR Signature    (Bytes 510-511)==
The exact offsets:

| Offset | Size      | Contents                  |
| ------ | --------- | ------------------------- |
| 0x000  | 446 bytes | Boot code / disk metadata |
| 0x1BE  | 16 bytes  | Partition entry 1         |
| 0x1CE  | 16 bytes  | Partition entry 2         |
| 0x1DE  | 16 bytes  | Partition entry 3         |
| 0x1EE  | 16 bytes  | Partition entry 4         |
| 0x1FE  | 2 bytes   | Signature `55 AA`         |

Each partition entry contains important information:
![[Pasted image 20261119135021.png|472]]

The table below shows the fields represented by these bytes. 

| Bytes Position | Bytes Length | Bytes       | Field Name           |
| -------------- | ------------ | ----------- | -------------------- |
| 0              | 1            | 80          | Boot Indicator       |
| 1-3            | 3            | 20 21 00    | Starting CHS Address |
| 4              | 1            | 07          | Partition Type       |
| 5-7            | 3            | FE FF FF    | Ending CHS Address   |
| 8-11           | 4            | 00 08 00 00 | Starting LBA Address |
| 12-15          | 4            | 00 B0 23 03 | Number of Sectors    |
Each field tells you something about the partition. Below is an explanation of all these fields:

1. **==Boot Indicator==:** This byte tells you whether the partition is bootable or not. A bootable partition contains files necessary for the operating system to boot. This boot indicator can only have one of the two values: `80` or `00`. If it's `80`, it means that the partition is bootable; else, if it's `00`, it means that the partition is not bootable.  In Windows based systems, **C:** is the partition that is typically bootable. If visualized through the partition table, this partition would have the boot indicator set to 80.
2. **==Starting CHS Address==:** Cylinder Head Sector (CHS) is the 3 bytes that tell you where this partition is starting from on the disk. It will give you the starting physical address of the partition, such as the cylinder, head, and sector number. This field is not that important as we now have the simplified logical address of the partition in the form of the Starting LBA Address discussed ahead.
3. **==Partition Type==:** Every partition uses a filesystem such as NTFS, FAT32, etc. This byte indicates the filesystem of the partition. The partition we are taking as a reference has this byte as `07`, which means it is an NTFS partition. Every filesystem has its own unique byte. You can learn about the bytes used for other filesystems from [here](https://www.writeblocked.org/resources/MBR_GPT_cheatsheet.pdf).
4. **==Ending CHS Address==:** The last 3 bytes at the end of the CHS Address indicates the physical location where the partition ends on the disk. This field is also not that important, just like the stated CHS address, as we mostly use the logical address (LBA) instead of the physical address.
5. **==Starting LBA Address==:** Logical Block Addressing (LBA) is the logical address that indicates the start of the partition. We saw that the Starting CHS Address also gives us the starting address of the partition, but because CHS gives you the physical address of the partition, it becomes difficult for us to locate it. However, the Starting LBA Address gives you the logical address of the partition rather than the physical address. You can use it to easily find the start of the partition on the disk in a hexadecimal editor. By locating the partition on the disk, you can also carve data from a disk's hidden or deleted partitions. Based on the partition we are analyzing as a reference with `00 08 00 00` LBA, we will use this logical address to locate our partition later in this task.
6. **==Number of Sectors==:** These last 4 bytes of a partition tell you the number of sectors in the partition. We will calculate the sector's size by using this field ahead.


**The important part:** MBR stores the starting LBA and partition size in each partition entry.

For example, a partition entry might say:

- Starting LBA = 2048
- Total sectors = 409600

The operating system calculates the end of the partition from those values.

MBR has only four primary partition entries. Extended partitions are a workaround for this limitation.

# **3. How GPT handles partitions**

GPT (GUID Partition Table) uses a different structure.

Instead of keeping all partition information in the first sector, it uses a **partition table header and an array of partition entries**.

For a typical disk with 512-byte logical sectors:

**GPT disk layout**

![[Pasted image 20261118113005.png]]
![[6645aa8c024f7893371eb7ac-1737110838398.svg|186]]
Notice that GPT maintains a backup of its partition metadata at the end of the disk. This helps recover the partition structure if the primary GPT metadata gets corrupted.

### Protective MBR:
**some legacy systems still use BIOS firmware even though the disk is GPT partitioned.**
*Protective MBR  is to signal the BIOS system that this disk is using the GPT, so please don't mess up with it thinking that it is the MBR.*
![[Pasted image 20261121072757.png|289]]
*it only has one partition in the table, and the other partitions are labeled with 0s. In this single partition, there is only one important thing: the 4th byte. This byte is set to `EE`, indicating that this is a GPT-formatted disk*
![[Pasted image 20261121073059.png|402]]
*and this partition has one job; to redirect the system to the EFI Partition*
 
### **What's inside the GPT header?**
*The GPT header starts right from the next byte (the start of sector 1) after the Protective MBR ends at `55 AA` (the end of sector 0). It acts as a blueprint of the partitions on the disk. All the bytes in the GPT header have a specific meaning. It has the whole 512 sector space but occupies the first 92 bytes of space, and after these 92 bytes, there would be all `00` bytes for padding purposes to complete the sector's total bytes. So, for the Primary GPT header, you only need to focus on the first 92 bytes, which can give you some meaningful information.*

The GPT header itself contains fields such as:
![[Pasted image 20261121073238.png|675]]

The table below shows the position of these bytes and their field names.

| Bytes Position | Bytes Length | Bytes                                           | Field Name                   |
| -------------- | ------------ | ----------------------------------------------- | ---------------------------- |
| 0-7            | 8            | 45 46 49 20 50 41 52 54                         | Signature                    |
| 8-11           | 4            | 00 00 01 00                                     | Revision                     |
| 12-15          | 4            | 5C 00 00 00                                     | Header Size                  |
| 16-19          | 4            | 71 89 13 1C                                     | CRC32 of Header              |
| 20-23          | 4            | 00 00 00 00                                     | Reserved                     |
| 24-31          | 8            | 01 00 00 00 00 00 00 00                         | Current LBA                  |
| 32-39          | 8            | AF 32 CF 1D 00 00 00 00                         | Backup LBA                   |
| 40-47          | 8            | 22 00 00 00 00 00 00 00                         | First Usable LBA             |
| 48-55          | 8            | 8E 32 CF 1D 00 00 00 00                         | Last Usable LBA              |
| 56-71          | 16           | 1D F1 B0 D6 43 BE 37 4E B1 E6 38 66 EC B1 73 89 | Disk GUID                    |
| 72-79          | 8            | 02 00 00 00 00 00 00 00                         | Partition Entry Array LBA    |
| 80-83          | 4            | 80 00 00 00                                     | Number of Partition Entries  |
| 84-87          | 4            | 80 00 00 00                                     | Size of Each Partition Entry |
| 88-91          | 4            | 41 0D C0 22                                     | CRC32 of Partition Array     |
1. **Signature:** This field has a value `45 46 49 20 50 41 52 54` which recognizes it as a GPT header. This value is always at the start of the GPT header.
2. **Revision:** The revision number is of 4 bytes and it represents the version of the GPT. Most of the times it would be `00 00 01 00` which means the GPT version is 1.0.
3. **Header Size:** This field represents the size of the GPT header. It is typically `5C 00 00 00` in hex and if you convert it to decimal (after reversing the order of bytes as they are in little-endian), it is 92 bytes which is the length of the GPT header.
4. **CRC32 of Header:** This is the CRC32 checksum of the GPT header, which if changed, would indicate that either the GPT header is tampered or corrupted.
5. **Reserved:** These are reserved bytes. The purpose of having them is to utilize them for any future changes in the GPT header.
6. **Current LBA:** The Current Logical Block Address (LBA) indicates the location of the GPT header. We know that its location is in sector 1, and we can verify this by converting the 8 Current LBA bytes `01 00 00 00 00 00 00 00` into decimal.
7. **Backup LBA:** In the GPT partitioning scheme, we have a backup of the GPT header as well. This field indicates the LBA of the backup GPT header.
8. **First Usable LBA:** This LBA address indicates the first address from which the partition can start on the disk.
9. **Last Usable LBA:** This LBA address indicates the last address to which the partitions on the disk can be written. Any partitions cannot occupy the disk space after the last usable LBA.
10. **Disk GUID:** This field is of 16 bytes and it presents a Globally Unique Identifier of the disk. The purpose of this GUID is to distinguish the disk from any other disks present in the system. In the current GPT header that we are analyzing, these bytes are `1D F1 B0 D6 43 BE 37 4E B1 E6 38 66 EC B1 73 89`. We can convert them to the standard GUID format of the disk by just reformatting them as `1DF1B0D6-43BE-374E-B1E6-3866ECB17389`.
11. **Partition Entry Array LBA:** This LBA address indicates the start of the Partition Entry Array 
12. **Number of Partition Entries:** This field indicates the number of partitions that are on the disk. The GPT supports 128 partitions, unlike the MBR, which supports 4 partitions only. The value of this field is `80 00 00 00` which if converted to decimal will be 128.
13. **Size of Each Partition Entry:** This field indicates the size occupied by each partition entry array. In this example, it set to `80 00 00 00` which is 128 in decimal. ==🟣It is important to note that== this is not the size of the partition itself. This is just the size of partition entry array.
14. **CRC32 of Partition Array:** This is the CRC32 checksum of the whole partition entry array, which if changed, would indicate that either the partition entry array is tampered or corrupted.


### **What's inside each GPT partition entry?**

A standard GPT partition entry is 128 bytes.
![[Pasted image 20261121080040.png|489]]

|Field|Size|Description|
|---|---|---|
|Partition type GUID|16 bytes|Identifies partition type|
|Unique partition GUID|16 bytes|Unique partition identifier|
|First LBA|8 bytes|Starting sector|
|Last LBA|8 bytes|Ending sector|
|Attributes|8 bytes|Partition flags|
|Partition name|72 bytes|UTF-16LE name|

![[Pasted image 20261121080456.png|637]]
The table below shows the fields represented by these bytes. 

|Bytes Position|Bytes Length|Bytes|Field Name|
|---|---|---|---|
|0-15|16|28 73 2A C1 1F F8 D2 11 BA 4B 00 A0 C9 3E C9 3B|Partition Type GUID|
|16-31|16|9E 43 0D 72 EC 12 54 44 8F B2 EE 17 8D F3 CD 3B|Unique Partition GUID|
|32-39|8|00 08 00 00 00 00 00 00|Starting LBA|
|40-47|8|FF 27 03 00 00 00 00 00|Ending LBA|
|48-55|8|00 00 00 00 00 00 00 80|Attributes|
|56-127|72|45 00 46 00 49 00 20 00 73 00 79 00 73 ...|Partition Name|
Each of these six fields has a specific purpose. Below is an explanation of all these fields. 

1. **Partition Type GUID:** This is the GUID of the partition type. This GUID will indicate the partition type, i.e., EFI System Partition, Basic Data Partition, etc. The 16 bytes of our partition entry are stored in mixed endian (little-endian and big-endian) format. This means we would have to reverse specific bytes and keep the other ones the same. In this case, we would do the following: use this script ("==🔴D:\HEXtoGUID.py==")

-  Reverse the first 4 bytes from `28 73 2A C1` to `C1 2A 73 28`, as they are in little-endian format.
-  Reverse the next 2 bytes from `1F F8` to `F8 1F`, as they are in little-endian format.
-  Reverse the next 2 bytes from `D2 11` to `11 D2` as they are in little-endian format.
- Keep the next 2 bytes `BA 4B` as it is, as they are in big-endian format.
-  Keep the last 6 bytes `00 A0 C9 3E C9 3B` as it is, as they are in big-endian format.

The resulting GUID from steps 1-5 will be `C12A7328-F81F-11D2-BA4B-00A0C93EC93B`. Whatever GUID you get from here, you can search it on the internet to get the partition type associated with that GUID. The GUID we calculated is used for EFI System Partition (ESP).

**==🔵EFI System Partition (ESP)==** is stored as a partition on every GPT disk and it is a very critical component in the boot process. In the MBR, we saw that the bootloaders are located in the bootcode and the bootable partition. In contrast, in the GPT, the bootloader is comprised of multiple files with **.efi** extension, and they all are stored in this EFI System Partition (ESP). Once the bootloader is found from the EFI System Partition, it loads the **Operating System's kernel** from the bootable partition of the disk, and after that, the drivers, services, and filesystems are loaded into the memory. Then the user is given the control of OS interface.

1. **Unique Partition GUID:** Unique Partition GUID is used to distinguish partitions on a disk. It is a unique GUID that is given to all the partitions on the disk. To convert these hexadecimal bytes into the standard GUID format, you can follow the same steps as we did for the first field (Partition Type GUID), as this is also stored in the mixed endian format.
2. **Starting LBA:** The starting LBA address indicates the area from where this partition starts on the disk. 
3. **Ending LBA:** The ending LBA address indicates the area at which this partition is ending on the disk.
4. **Attributes:** This field contains some flags that indicates some features of the partition, for example, if it is bootable, hidden, or normal.[^3]
5. **Partition Name:** This is the last field of the partition entry, and its size is 72 bytes. It represents the name of the partition in string format and is UTF-16 encoded. If you decode these bytes using any online hex-to-string decoder, you will get the partition name of this partition.
___
### Backup GPT Header

One of the biggest reasons the GPT replaced the MBR is its redundancy. In case of the MBR, if your MBR gets corrupted or changed due to hardware issues or malicious attacks, you have a minimal chance of recovery. On the other hand, the GPT has backups of its components. The Backup GPT Header is located at the last sector of the disk, and it can be used for recovery in case the Primary GPT Header is corrupted. It contains the same information as the Primary GPT Header.
____
### Backup Partition Entry Array

There is also a backup copy of the partition entry array. It is stored at the end of the disk just before the backup GPT header. It contains the same information as the partition entry array. It acts as a fail-safe mechanism in case the original partition entry array is damaged.
____

# **4. MBR vs GPT at the hexadecimal level**

Let's compare what happens when both partition schemes describe a partition starting at LBA 2048.

**MBR:**

The starting LBA is stored in 4 bytes (little-endian):

```
00 08 00 00
```

**GPT:**

The starting LBA is stored in 8 bytes (little-endian):

```
00 08 00 00 00 00 00 00
```

Both represent decimal 2048.

The difference is that GPT uses 64-bit LBA fields, whereas MBR uses 32-bit LBA fields.

This is one of the reasons GPT supports much larger disks.

# **5. Where do your actual C: and D: partitions start?**

We cannot calculate their exact starting LBAs from their capacities alone. We need the actual partition offsets.

Run this PowerShell script:

```
$disk = Get-Disk -Number 0
$sectorSize = $disk.LogicalSectorSize

Get-Partition -DiskNumber 0 | ForEach-Object {
    [PSCustomObject]@{
        Partition       = $_.PartitionNumber
        Drive           = $_.DriveLetter
        Type            = $_.Type
        StartingOffset  = $_.Offset
        StartingLBA     = $_.Offset / $sectorSize
        SizeGB          = [math]::Round($_.Size / 1GB, 2)
    }
} | Format-Table -AutoSize
```
This will tell us:

- The partition number.
- Its drive letter, if assigned.
- Its starting byte offset.
- Its starting LBA.
- Its size.
![[Pasted image 20261118113113.png]]
[[on my own pc]]
You can then inspect the raw disk bytes using a hex editor such as HxD.

[hard drive - Why does a GPT formatted disk have the MBR? Protective MBR - Super User](https://images.openai.com/static-rsc-4/MqkBtlEwsjA_RjMLONvH2hEWQdRnm2jsAEFYFhov_4kFh2uf135OqBZIs2YdYW6dbTWNDRkRQS3Rqv1u5gmDiIvSjr873Tfy62ucuy-JiyWjiY5NLQUQExT74uOoD2NXJPzZFJxl3BVSq-KfFcu4rLLH93w5kdkgh4ydiBKkOig?purpose=inline)

[superuser.com](https://superuser.com/questions/1766814/why-does-a-gpt-formatted-disk-have-the-mbr-protective-mbr?utm_source=chatgpt.com)

# **6. The most important takeaway**

Think of it this way:

|Question|Who answers it?|
|---|---|
|Where does the partition start?|GPT / MBR|
|Where does the partition end?|GPT / MBR|
|Which partition is EFI?|GPT partition type GUID|
|Which file system is used?|NTFS / FAT32 metadata|
|Where is a particular file stored?|File system metadata and allocation structures|
|Which physical device stores the data?|HDD / SSD hardware|

**A useful distinction for digital forensics:** GPT tells you where a partition begins, but NTFS tells you how files are organized within that partition.

[^1]: This Bootloader code contains the **Initial Bootloader**. The initial bootloader is the first thing that executes in the MBR. This initial bootloader code has a primary purpose of finding the ==🟡bootable partition== from the **partition table** present on the MBR.

[^2]: This table contains the details of all the partitions present on the disk. One of the partitions in the disk contains all the operating system files necessary for booting, known as a bootable partition. The ==🟡initial bootloader== that was started from the bootloader code of the MBR  finds the bootable partition from this partition table, and it loads the ==🟢second bootloader== from it. The second bootloader then loads the **Operating System's Kernel**. A partition table is used during this boot process.

[^3]: |**Bit**|**Hex Mask (64-bit)**|**Flag Name**|**Meaning**|
	|---|---|---|---|
	|**Bit 60**|`0x1000000000000000`|**Read-Only**|Forces the OS to mount the partition as read-only, preventing any modifications.|
	|**Bit 61**|`0x2000000000000000`|**Shadow Copy**|Marks the volume as a Volume Shadow Copy Service (VSS) snapshot.|
	|**Bit 62**|`0x4000000000000000`|**Hidden**|Hides the partition from standard OS mount managers and File Explorer.|
	|**Bit 63**|`0x8000000000000000`|**No Drive Letter** (Do Not Automount)|Prevents Windows from automatically assigning a drive letter to the partition when detected.|
