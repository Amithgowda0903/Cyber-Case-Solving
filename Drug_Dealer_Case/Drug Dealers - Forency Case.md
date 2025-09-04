
```bash
Note : This links were of a former case, but required packages are not getting installed, so proceed with the next case.

https://cfreds-archive.nist.gov/data_leakage_case/images/pc/cfreds_2015_data_leakage_pc.7z.001

https://cfreds-archive.nist.gov/data_leakage_case/images/pc/cfreds_2015_data_leakage_pc.7z.002

https://cfreds-archive.nist.gov/data_leakage_case/images/pc/cfreds_2015_data_leakage_pc.7z.003
```

[click here](https://drive.google.com/file/d/19GWWbUsNvyjpcuvVw2NH4PlieKgE2RC8/view?usp=drive_link) to download the case

### **1️⃣ Hash Verification**

**Objective:** Verify integrity of provided PC image files.  
**Tools Used:** `file`,`md5sum`,`sha1sum`,`sha256sum`

| File                                    | MD5                                | SHA-1                                      |
| --------------------------------------- | ---------------------------------- | ------------------------------------------ |
| Chrome_History_Cryptocurrency_Lab.db    | `0c594e9de87348c089554953a67e2c74` | `e14ad4c53c44cafd286c78bd4073e1fd02d1af00` |
| Chrome_History_Recreation_Craigslist    | `a70f8d20d5c7740100a98eb7a2d2ebf6` | `024738ee51ea05f5cff3a891cf6b1372ba12529f` |
| Chrome_History_Recreation_Gmail         | `b7a406c9487cd590486e292c5da195f9` | `382d90f195ec3b753a375851d163c1875e5cbd19` |
| Chrome_History_Recreation_Gmail_Headers | `7206b9718c710b95ef52408122bbd845` | `1c8edcea710569d3ee30b4df10f4c9f8d6a7636c` |
| History                                 | `0c594e9de87348c089554953a67e2c74` | `e14ad4c53c44cafd286c78bd4073e1fd02d1af00` |
| Chrome_History_Recreation_Imgur         | `32f23e0a7a67fd99ff52d66dac4690f7` | `f76cee789c453539b0a3d017c0948b9ef4c44aba` |
| Chrome_History_to_Database_Demo         | `1bf62feb7b4534a2c289418ad149d9f2` | `5ab046e8fdef9f86bf01a34d0a9a5dc71451f27b` |

💡 **Conclusion:** Hash values match — confirms integrity.

---

### **2️⃣ Partition Information**

**Tools:** `binwalk`, `fdisk -l <file>`, Autopsy, Mount option in GUI.

- **Purpose:** Identify file system layout and partitions.
    
- Using `fdisk` or Autopsy reveals:
    
    - Partition type(s)
        
    - Bootable flags
        
    - File system (e.g., NTFS, FAT32, ext4)
        
    - Start and end sectors, total size.
    
    `| Note :  If you have a iso file just go to it and right click and there you get a option called mount jut click it and now you get to see an option under my pc that will be shown as one of the drive. where you can see the files of the OS. Later if you want to unmount it just right click and eject it.`
---

### **3️⃣ OS Information**

**Goal:** Identify OS name, installation date, registered owner, timezone, computer name, and other system details from a forensic image.

### **Location of Relevant Files**

#### *For Windows*

- Path:
    
    ```
    C:\Windows\System32\config
    ```
    
- Important Registry Hive Files:
    
    1. **SOFTWARE** – Installed software details, OS product info.
        
    2. **SYSTEM** – Timezone settings, system state, hardware configs.
        
    3. **SAM** – User account information.
        

#### *For Linux*

- Look for equivalent configuration files (may differ by distro).
    
- Use:
    
    ```bash
    locate software
    locate system
    locate sam
    ```
    
- Config files in `/etc`, `/var`, and user home directories may hold install & timezone info.
    

---

### **🔍 Purpose of Key Registry Hives**

#### **1. SOFTWARE Hive**

- **Contains:**
    
    - OS **Product Name**
        
    - **Install Date**
        
    - **Registered Owner**
        
    - Installed software list
        
    - Installation/uninstallation timestamps
        
    - Publisher information
        

#### **2. SAM Hive**

- **Contains:**
    
    - Local user accounts
        
    - Group policies
        
    - Password hashes
        
- **Example Forensic Task:**  
    List all accounts except system accounts:
    
    - Administrator
        
    - Guest
        
    - systemprofile
        
    - LocalService
        
    - NetworkService  
        _(Include: account name, login count, last logon date)_
        

#### **3. SYSTEM Hive**

- **Contains:**
    
    - Timezone setting (**TimeZoneKeyName**)
        
    - Computer Name
        
    - Last recorded shutdown date/time
        
    - Last user logged on
        
    - Network interface info (DHCP-assigned IP addresses)
        
    - Application execution logs:
        
        - Executable path
            
        - Execution time
            
        - Execution count
            

---

### **🗝 Important Registry Keys**


| Information      | Registry Path                                                 | Key Name        |
| ---------------- | ------------------------------------------------------------- | --------------- |
| OS Name          | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`           | ProductName     |
| Install Date     | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`           | InstallDate     |
| Registered Owner | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`           | RegisteredOwner |
| Timezone         | `HKLM\SYSTEM\ControlSet001\Control\TimeZoneInformation`       | TimeZoneKeyName |
| Computer Name    | `HKLM\SYSTEM\ControlSet001\Control\ComputerName\ComputerName` | ComputerName    |

`| NOTE: `  Here is the sample image of the path 
`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`

![[Pasted image 20250719185009.png]]

---

### **💡 Example Forensic Findings**

_(To be filled after hive extraction & analysis)_

- **OS Name:** Windows 10 Pro
    
- **Install Date:** `YYYY-MM-DD HH:MM:SS`
    
- **Registered Owner:** `John Doe`
    
- **Timezone:** `India Standard Time` (UTC+5:30)
    
- **Computer Name:** `PC-FORENSICS`
    
- **Last Shutdown:** `YYYY-MM-DD HH:MM:SS`
    
- **Last Logged-in User:** `johnd`
    
- **DHCP IP Address:** `192.168.0.105`
    
- **Top Applications Executed:** Chrome, cmd.exe, notepad.exe

---

### **4️⃣ Web Browser History Paths**

**Location:**

- Chrome History (SQLite DB):  
    `C:\Users\<username>\AppData\Local\Google\Chrome\User Data\Default\History`
    

**Important Tables:**

- **downloads** → File type, saved location, download time.
    
- **urls** → Visited URLs, page titles, last visit time.
    
- **visits** → Visit count, duration, timestamps.

Here is the sample command for `Reglookup` :
```bash
reglookup /mnt/pc_image/Windows/System32/config/SOFTWARE | grep -E "ProductName|InstallDate|RegisteredOwner"
reglookup /mnt/pc_image/Windows/System32/config/SYSTEM | grep -E "TimeZoneKeyName|ComputerName"
reglookup /mnt/pc_image/Windows/System32/config/SAM | grep -i "Account"
```

### **Notes for Forensic Reports**
- `reglookup` outputs timestamps in **UTC** — convert to local time for readability.
- `mnt/pc_image` is the mounted hive path of the of the victims PC.
-  use `grep` to filter any targeted key — `reglookup SOFTWARE | grep -i ProductName`

---

### **5️⃣ Websites Visited**

The tool used to find the details of the `.db` files is `sqlitebrowser`
The following command helps to open the file `sqlitebrowser <file>.db`
Extracted from Chrome history SQLite DBs:

| Visit ID | Date (IST)          | Description                                         |
| -------- | ------------------- | --------------------------------------------------- |
| 1        | 2022-04-19 19:24:18 | Searching for Craigslist in Google search           |
| 2        | 2022-04-19 19:24:18 | Redirected to main Craigslist home page             |
| 3        | 2022-04-19 19:24:18 | As per current location, Craigslist page is loading |
| 4        | 2022-04-19 19:24:18 | Craigslist page loaded for Baltimore location       |
| 5        | 2022-04-19 19:24:18 | Craigslist login page                               |
| 6        | 2022-04-19 19:24:18 | Craigslist login page                               |
| 7        | 2022-04-19 19:24:18 | Craigslist selection page for type of posting       |
| 8        | 2022-04-19 19:24:18 | Link not open (404 error)                           |
| 9        | 2022-04-19 19:24:18 | Link not open (404 error)                           |
| 10       | 2022-04-19 19:24:18 | Link not open (404 error)                           |
| 11       | 2022-04-19 19:24:18 | Link not open (404 error)                           |
| 12       | 2022-04-19 19:24:18 | Link not open (404 error)                           |
| 13       | 2022-04-19 19:24:18 | Link not open (404 error)                           |
| 14       | 2022-04-19 19:24:18 | Link not open (404 error)                           |
| 15       | 2022-04-19 19:24:18 | Craigslist login page                               |
| 16       | 2022-04-19 19:24:18 | Link not open (404 error)                           |
| 17       | 2022-04-19 19:24:18 | Searching for Google Gmail in Google search         |
| 18       | 2022-04-19 19:24:18 | Main Gmail website opened                           |
| 19       | 2022-04-19 19:24:18 | Main Gmail website opened                           |
| 20       | 2022-04-19 19:24:18 | Main Gmail website opened                           |
| 21       | 2022-04-19 19:24:18 | Main Gmail website opened                           |
| 22       | 2022-04-19 19:24:18 | _(Description not available)_                       |
| 23       | 2022-04-19 19:24:18 | _(Description not available)_                       |
| 24       | 2022-04-19 19:24:18 | _(Description not available)_                       |
| 25       | 2022-04-19 19:24:18 | _(Description not available)_                       |
| 26       | 2022-04-19 19:24:18 | _(Description not available)_                       |
| 27       | 2022-04-19 19:24:18 | _(Description not available)_                       |

**Timestamp Conversion:**

```bash
date -d @$(echo "scale=0; (13294850058231547 - 11644473600000000) / 1000000" | bc)
# Tue Apr 19 19:24:18 IST 2022
```

---

### **6️⃣ Case Assumptions**

1. Suspected drug dealer posted ad on Craigslist.
    
2. Buyer contacted dealer.
    
3. Dealer replied with Bitcoin wallet details.
    
4. Buyer sent payment.
    
5. Dealer confirmed payment.
    
6. Dealer shipped drugs.
    
7. Buyer received drugs.
    

---

### **🔧 Tools Used**

- **Hashing:** `md5sum`, `sha1sum`, `sha256sum`
    
- **Partition Analysis:** `fdisk`, `binwalk`, Autopsy
    
- **Registry Analysis:** Reglookup, Hivex, FTK Imager
    
- **Browser History:** `sqlitebrowser`, Chrome History DB
    

---
#forency 