##  Forensic Image Mounting

### 1. Verify Image Hashes

Before doing any analysis, always compute checksums to verify integrity:

```bash
md5sum 4Dell\ Latitude\ CPi.E01
sha1sum 4Dell\ Latitude\ CPi.E01
```

**Output (example):**

```
MD5 : 943243e71eda7481fee7b83f06698993
SHA1: ff2bedb4ab9ee139cd4403b2e3424df368673fe2
```

---

### 2. Install Required Tools

```bash
sudo apt update
sudo apt install ewf-tools ntfs-3g
```

---

### 3. Prepare Mount Directories

```bash
sudo mkdir -p /mnt/image
```

(remove any old ones if necessary)

```bash
sudo rm -rf /mnt/ewf /mnt/partition
```

---

### 4. Mount the E01 Image

Use **ewfmount** to mount the forensic image:

```bash
sudo ewfmount 4Dell\ Latitude\ CPi.E01 /mnt/image/
```

This creates a **virtual device** inside `/mnt/image/` (usually named `ewf1`).

---

### 5. Inspect the Mounted Image

Change into the mount point:

```bash
cd /mnt/image
ls
```

Check the partition structure using `mmls`:

```bash
sudo mmls ewf1
```

This shows partition layout, start sectors, and filesystem info.

---

### 6. Mount the Partition (if needed)

Once you identify the partition offset from `mmls`, mount it:

```bash
sudo mount -o ro,loop,offset=$((START_SECTOR*512)) ewf1 /mnt/partition
```

_(Replace `START_SECTOR` with the sector offset from `mmls` output)_

---

### 7. Examine Partition Table with `mmls`

```bash
cd /mnt/image/
ls
sudo mmls ewf1
```

- Output shows partition layout.
    
- In your case, **starting sector = 63**.
    
- Offset in bytes = `63 * 512 = 32256`.
    

---

### 8. Create Mount Point for Partition

```bash
sudo mkdir /mnt/partition
```

---

### 9. Mount NTFS Partition (Read-Only)

```bash
sudo ntfs-3g -o ro,loop,offset=32256 ewf1 /mnt/partition/
```

Now, files are accessible under `/mnt/partition`.

---

### 10. Install Sleuth Kit / Autopsy (if not already)

```bash
sudo apt install autopsy sleuthkit
```

---

### 11. File Listing with `fls`

Use **fls** (forensic file system listing):

```bash
fls -r -o 63 ewf1
```

- `-r` = recursive
    
- `-o 63` = partition offset in sectors
    

Filter results:

```bash
fls -r -o 63 ewf1 | grep "DOCUMENT"
fls -r -o 63 ewf1 | grep "system"
fls -r -o 63 ewf1 | grep "-/d"
```

- `-/d` indicates directories
    
- `-/r` would show regular files
    

---

### 12. Extract a File with `icat`

When you identify an inode (e.g., 3646), extract with:

```bash
icat -o 63 ewf1 3646 > system.ini
```

This saves the file **system.ini** to your working directory.

⚠️ The command you tried:

```bash
icat -o 63 ewf1 3646-128-3 > system.ini
```

is **incorrect**. `icat` takes a single inode address, not a range. Stick to:

```bash
icat -o 63 ewf1 <inode> > filename
```

---

### 🔹 At This Stage

- You’ve **mounted** the partition.
    
- You’ve used **fls** to **list files/directories**.
    
- You’ve used **icat** to **recover files by inode**.
    
- You’re ready to analyze contents or use **Autopsy** for GUI-based examination.
    

### 13) **Verify extracted files**

Every file you carve with `icat` should be hashed immediately:

```bash
md5sum /home/system /home/kali/powerpnt.ppt
sha1sum /home/system /home/kali/powerpnt.ppt
```

→ Save into an evidence log.

---

### 14) **Identify file types properly**

```bash
file /home/system /home/kali/powerpnt.ppt
```

If something looks suspicious (e.g., mislabeled or obfuscated), note it.

---

### 15) **Inspect filesystem metadata**

For each inode you’re extracting:

```bash
istat -o 63 ewf1 9741
istat -o 63 ewf1 9756
```

→ This gives MAC timestamps (created, modified, accessed) = critical for timeline.

---

### 16) **Build a Timeline**

You already ran `fls`. Now formalize it:

```bash
fls -r -o 63 ewf1 > /home/kali/bodyfile.txt
mactime -b /home/kali/bodyfile.txt > /home/kali/timeline.txt
less /home/kali/timeline.txt
```

→ Lets you see when “system.ini” or “powerpnt.ppt” was created/modified/deleted.

---

### 17) **Deep dive into content**

- `strings` search:
    
    ```bash
    strings -n 6 /home/system | less
    strings -n 6 /home/kali/powerpnt.ppt | grep -i "http"
    ```
    
- Metadata:
    
    ```bash
    exiftool /home/kali/powerpnt.ppt
    ```
    

---

### 18) **Bulk recovery (if needed)**

Instead of inode-by-inode:

```bash
sudo mkdir -p /home/kali/recovered
sudo tsk_recover -o 63 ewf1 /home/kali/recovered/
```

---

### 19) **Keyword / artifact search**

Example: looking for executables, documents, passwords:

```bash
fls -r -o 63 ewf1 | grep -i ".exe"
fls -r -o 63 ewf1 | grep -i "password"
grep -R -i "password" /mnt/partition/ 2>/dev/null
```

---

### 20) **Use Autopsy (optional GUI)**

Since you installed it:

```bash
sudo autopsy
```

→ Open browser at `http://127.0.0.1:9999`, create a case, add your `ewf1` as evidence, explore GUI-based artifacts (browser history, email, docs, etc.).

---

### 21) **Documentation**

- Export your shell history:
    
    ```bash
    history > /home/kali/forensic_commands_used.txt
    ```
    
- Save hash logs, `istat` output, `timeline.txt`, and file metadata into a case folder.
    

