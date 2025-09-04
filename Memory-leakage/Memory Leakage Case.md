### **Introduction**

Volatility is an **open-source memory forensics framework** used for extracting digital artifacts from RAM dumps.  
It helps in **incident response**, **malware analysis**, and **digital investigations** by revealing:

- Running processes & terminated processes
    
- Loaded DLLs & drivers
    
- Network connections
    
- Registry keys & values
    
- User activity & configuration settings
    
- Evidence of malware or hidden code
    

**Common Use Cases**:

- Analyzing malware infections
    
- Investigating compromised systems
    
- Extracting forensic evidence from volatile memory
    
- Incident response in cybersecurity investigations
    

---

## **Practical Steps – Registry Key Extraction**

### **1️⃣ Install Volatility (v2 for Python2)**

```bash
# Clone Volatility repo
git clone https://github.com/volatilityfoundation/volatility.git

# Go into the directory
cd volatility

# Check if Python2 is available
python2 --version
```

---

### **2️⃣ Install Required Dependencies**

Since Volatility v2 runs on Python2.7, you need pip for Python2 and required libraries:

```bash
# Install pip for Python2
curl https://bootstrap.pypa.io/pip/2.7/get-pip.py -o get-pip.py
sudo python2.7 get-pip.py

# Install dependencies
sudo apt update
sudo apt install python2-dev build-essential

# Python packages
pip2 install pycrypto setuptools distorm3
```

**Note:**

- `python2-dev` → Headers for compiling Python extensions
    
- `build-essential` → gcc, g++, make (required for compilation)
    
- `distorm3` → Required for disassembly in Volatility
    

---

### **3️⃣ Move Memory Dump to Volatility Folder**

 ```bash
wget https://www.dropbox.com/scl/fi/1y68wpuiq1fsvrapq9egg/?rlkey=pk3thrk3p2fk9m90mywksx3s1

mv memdumpWin7.mem /home/kali/Downloads/volatility
cd /home/kali/Downloads/volatility
```

---

### **4️⃣ Identify the Memory Image Profile**

```bash
python2 vol.py -f memdumpWin7.mem imageinfo
```

**Output Example:**

```
Suggested Profile(s) : Win7SP1x86_23418, Win7SP1x86
```

This tells Volatility which OS profile matches the memory dump.

---

### **5️⃣ Extract Registry Key: Volatile Environment**

```bash
python2 vol.py -f memdumpWin7.mem --profile=Win7SP1x86_23418 printkey
```

From the output, find a registry path like:

```
C:\Users\IEUser\ntuser.dat
```

*This is to find the USER PROFILE*
**Get details of Volatile Environment:**

```bash
python2 vol.py -f memdumpWin7.mem --profile=Win7SP1x86_23418 \
  printkey -K "Volatile Environment"
```

**Example Output:**

```
LOGONSERVER  : \\IE8WIN7
USERDOMAIN   : IE8WIN7
USERNAME     : IEUser
USERPROFILE  : C:\Users\IEUser
...
```

---

### **6️⃣ Explore Microsoft ProfileList Registry**

**View ProfileList key:**

```bash
python2 vol.py -f memdumpWin7.mem --profile=Win7SP1x86_23418 \
  printkey -K "Microsoft\Windows NT\CurrentVersion\ProfileList"
```

Shows subkeys like:

```
S-1-5-18
S-1-5-19
S-1-5-20
S-1-5-21-1716914095-909560446-1177810406-1000
S-1-5-21-1716914095-909560446-1177810406-1002
```

---

### **7️⃣ View Each User Profile Info**

For each SID:

```bash
python2 vol.py -f memdumpWin7.mem --profile=Win7SP1x86_23418 \
  printkey -K "Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-21-1716914095-909560446-1177810406-1000"

python2 vol.py -f memdumpWin7.mem --profile=Win7SP1x86_23418 \
  printkey -K "Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-21-1716914095-909560446-1177810406-1002"
```

These reveal the actual folder paths & user information.

---

### **8️⃣ Find Logon User – Winlogon Key**

```bash
python2 vol.py -f memdumpWin7.mem --profile=Win7SP1x86_23418 \
  printkey -K "Microsoft\Windows NT\CurrentVersion\Winlogon"
```

**Purpose:**  
Retrieves the **Winlogon** registry key from memory, which contains login settings.

**Key Values:**

- `DefaultUserName` → Current logon username (`IEUser`)
    
- `AutoAdminLogon` → If `1`, auto-login is enabled
    
- `Shell` → Default shell (`explorer.exe`)
    
- `Userinit` → Program run after login (`userinit.exe`)
    

✅ **Why Important:**  
Tells the investigator **who was logged in** at the time of the memory capture.

---

### **9️⃣ List All Registry Hives in Memory**

```bash
python2 vol.py -f memdumpWin7.mem --profile=Win7SP1x86_23418 hivelist
```

**Purpose:**  
Lists the registry hives loaded in memory with both **virtual** and **physical** addresses.

**Example Findings:**

```
\??\C:\Users\IEUser\ntuser.dat
\??\C:\Users\sshd_server\ntuser.dat
```

- `NTUSER.dat` → Stores **user-specific registry data** (desktop settings, app configs, etc.)
    
- Can be parsed to extract user activity history.
    

💡 **Tip:** The `hivelist` output helps you locate exact hive paths for deeper analysis.

---

### **🔟 Extract Processor Details**

#### **Central Processor (CPU)**

```bash
python2 vol.py -f memdumpWin7.mem --profile=Win7SP1x86_23418 \
  printkey -K "DESCRIPTION\System\CentralProcessor\0"
```

Shows details like CPU name, vendor, and speed.

#### **System Processor Info**

```bash
python2 vol.py -f memdumpWin7.mem --profile=Win7SP1x86_23418 \
  printkey -K "DESCRIPTION\System"
```

Displays higher-level processor/system configuration.

✅ **Why Important:**  
Helps identify the **hardware environment** in which the system was running.

---

### **1️⃣1️⃣ Identify Connected Devices**

#### **List All Connected Devices**

```bash
python2 vol.py -f memdumpWin7.mem --profile=Win7SP1x86_23418 \
  printkey -K "ControlSet001\Enum"
```

Shows hardware and peripherals connected to the machine.

#### **PCI Devices (Detailed IDs)**

```bash
python2 vol.py -f memdumpWin7.mem --profile=Win7SP1x86_23418 \
  printkey -K "ControlSet001\Enum\PCI"
```

Example Subkeys:

```
(S) VEN_1000&DEV_0054&SUBSYS_1F091028&REV_01
(S) VEN_1002&DEV_515E&SUBSYS_01E61028&REV_02
(S) VEN_1022&DEV_2000&SUBSYS_20001022&REV_40
(S) VEN_106B&DEV_003F&SUBSYS_00000000&REV_00
(S) VEN_14E4&DEV_1659&SUBSYS_01E61028&REV_11
(S) VEN_15AD&DEV_0790&SUBSYS_079015AD&REV_02
(S) VEN_15AD&DEV_07A0&SUBSYS_07A015AD&REV_01
(S) VEN_8086&DEV_032C&SUBSYS_00000000&REV_09
(S) VEN_8086&DEV_100E&SUBSYS_001E8086&REV_02
(S) VEN_8086&DEV_1237&SUBSYS_00000000&REV_02
(S) VEN_8086&DEV_265C&SUBSYS_00000000&REV_00
(S) VEN_8086&DEV_2778&SUBSYS_01E61028&REV_00
(S) VEN_8086&DEV_2779&SUBSYS_01E61028&REV_00
(S) VEN_8086&DEV_27C8&SUBSYS_01E61028&REV_01
(S) VEN_8086&DEV_27C9&SUBSYS_01E61028&REV_01
(S) VEN_8086&DEV_27CA&SUBSYS_01E61028&REV_01
(S) VEN_8086&DEV_27CC&SUBSYS_01E61028&REV_01
(S) VEN_8086&DEV_27D0&SUBSYS_01E61028&REV_01
(S) VEN_8086&DEV_27DF&SUBSYS_01E61028&REV_01
(S) VEN_8086&DEV_27E0&SUBSYS_01E61028&REV_01
(S) VEN_8086&DEV_27E2&SUBSYS_01E61028&REV_01
(S) VEN_8086&DEV_7000&SUBSYS_00000000&REV_00
(S) VEN_8086&DEV_7190&SUBSYS_197615AD&REV_01
(S) VEN_8086&DEV_7192&SUBSYS_00000000&REV_03
(S) VEN_80EE&DEV_BEEF&SUBSYS_00000000&REV_00
(S) VEN_80EE&DEV_CAFE&SUBSYS_00000000&REV_00


these are the device ID where we can check the product drivers.
                                                                   
```

**How to Use IDs:**

- `VEN_xxxx` → Vendor ID
    
- `DEV_xxxx` → Device ID  
    Search these IDs online to identify **hardware models** and **drivers**.
    

✅ **Why Important:**  
Reveals the system’s hardware profile, which can:

- Identify virtual environments (VM detection)
    
- Reveal connected devices like storage, network adapters, GPUs
    

---

## **📌 Investigator’s Notes**

- Always **run `imageinfo` first** to determine the correct profile.
    
- Use `printkey` to read registry keys directly from the memory image.
    
- Hardware IDs (`VEN`/`DEV`) can confirm **if a system was physical or virtualized**.
    
- `NTUSER.dat` locations from `hivelist` are a goldmine for user-specific activity.
    
- The `imageinfo` command must always be run first to identify the correct profile.
    
- Registry analysis from memory dumps does not require access to the actual host’s registry — it reads it directly from RAM.
    
- `Volatile Environment` registry key contains **session-specific variables** such as `USERNAME`, `LOGONSERVER`, and `USERPROFILE`.
    
- `ProfileList` registry key maps **Security Identifiers (SIDs)** to user profile folders.
    
---
#forency 


Alright, I’ll rewrite all of your commands into a **clean, step-by-step note** so it’s easier to follow next time.  
I’ll group them into **Installation**, **Configuration**, and **Execution** stages for clarity.

---

## **Volatility 2 + Yara Integration Notes (Python 2.7)**

> Tested on Kali Linux, root terminal

---

### **1️⃣ Install Required Dependencies**

```bash
# System dependencies
sudo apt-get install automake libtool make gcc pkg-config flex bison python-pip python-dev

# Python 2 dependencies for Volatility
pip2 install pycrypto==2.6.1
pip2 install distorm3==3.4.4
pip2 install yara-python==3.8.0
```

**Why:**

- `pycrypto` → fixes `No module named Crypto.Hash`
    
- `distorm3` → fixes disassembly plugin errors
    
- `yara-python 3.8.0` → last version compatible with Python 2 Volatility
    

---

### **2️⃣ Compile & Install Yara from Source (Optional)**

Only if you want latest Yara CLI for testing, not necessary for Volatility 2:

```bash
wget https://github.com/VirusTotal/yara/archive/refs/tags/v4.5.4.zip
unzip v4.5.4.zip
cd yara-4.5.4

./bootstrap.sh
./configure --enable-cuckoo --enable-magic --enable-dotnet
make
sudo make install
make check
```

Update library path:

```bash
sudo sh -c 'echo "/usr/local/lib" >> /etc/ld.so.conf'
sudo ldconfig
```

Test Yara:

```bash
yara --version
```

---

### **3️⃣ Install Volatility 2 (Source)**

```bash
cd volatility # inside 2nd volatility folder
sudo python2 setup.py install
```

If `volatility` command is not found:

```bash
python2 vol.py -h    # Run directly from source folder
```

Or locate installation:

```bash
sudo find / -name volatility -type f 2>/dev/null
```

*if anything like`/usr/local/bin` is to be seen then run the following command*
Add to PATH if needed:

```bash
export PATH=$PATH:/usr/local/bin
```

---

### **4️⃣ Run Yara Scan in Volatility**

Example with output to file:

```bash
python2 vol.py -f memdumpWin7.mem --profile=Win7SP1x86_23418 yarascan \
    -Y "192.168.56.5" --output-file=info.txt
```

View results:

```bash
cat info.txt
```

---

### **5️⃣ Troubleshooting**

- **`No module named Crypto.Hash`** → install `pycrypto==2.6.1`
    
- **`name 'distorm3' is not defined`** → install `distorm3==3.4.4`
    
- **`Please install Yara`** → install `yara-python==3.8.0` for Python 2
    
- **`volatility: command not found`** → run `python2 vol.py` from source or add install path to `PATH`
    

---

If you want, I can also make you a **single shell script** that automates all these steps so you can set up Volatility 2 + Yara on a fresh Kali in one go. That would save you from repeating these 50+ commands.