# Tripwire

A Python-based digital forensics tool for **real-time detection and snapshotting of temporary files** created by malware.  
Ideal for **dynamic analysis** of fileless malware and monitoring suspicious file events during runtime.

---

### Features:
- Monitor multiple file system paths.
- Specify file extensions to detect.
- Real-time monitoring **0.1 second delay**.
- Exclude specific file types from monitoring.

---

### Usage:

#### Executable (Recommended)
```bash
.\Tripwire.exe
```

#### Python
```bash
pip install watchdog colorama
git clone https://github.com/yourusername/Tripwire.git
python Tripwire.py
cd Tripwire
```

### Example:

![Tripwire in Action](https://github.com/user-attachments/assets/265b1abd-49c2-4613-95af-aa5df3883e17)
