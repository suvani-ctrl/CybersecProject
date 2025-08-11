# Malware Family Label Mapping Guide

This guide shows the mapping between numeric labels used by the models and their corresponding malware family names.

## Label Mapping

| Number | Malware Family | Description | Danger Level | Emoji |
|--------|----------------|-------------|--------------|-------|
| 0 | report_backdoor | Backdoor malware | HIGH | 🔓 |
| 1 | report_clean | Clean/legitimate files | SAFE | ✅ |
| 2 | report_coinminer | Cryptocurrency mining malware | MEDIUM | ⛏️ |
| 3 | report_dropper | Malware that delivers other programs | HIGH | 📦 |
| 4 | report_keylogger | Keystroke logging malware | HIGH | ⌨️ |
| 5 | report_ransomware | File encryption ransomware | CRITICAL | 🔐 |
| 6 | report_rat | Remote Access Trojan | HIGH | 🕷️ |
| 7 | report_trojan | Trojan horse malware | HIGH | 🐴 |
| 8 | report_windows_syswow64 | Windows system files | SAFE | 🖥️ |

## Family Details

### 🔓 Backdoor (0)
- **Description**: Malware that creates secret access points to your system
- **Danger Level**: HIGH
- **Threats**: Remote access, Data theft, System control, Network compromise

### ✅ Clean (1)
- **Description**: Safe, legitimate files
- **Danger Level**: SAFE
- **Threats**: No threats detected

### ⛏️ Coinminer (2)
- **Description**: Cryptocurrency mining malware
- **Danger Level**: MEDIUM
- **Threats**: Resource theft, System slowdown, Hardware damage, High power usage

### 📦 Dropper (3)
- **Description**: Malware that delivers other malicious programs
- **Danger Level**: HIGH
- **Threats**: Multiple infections, Antivirus bypass, System compromise, Data theft

### ⌨️ Keylogger (4)
- **Description**: Malware that records your keystrokes
- **Danger Level**: HIGH
- **Threats**: Password theft, Credit card theft, Privacy violation, Identity theft

### 🔐 Ransomware (5)
- **Description**: Malware that encrypts your files and demands payment
- **Danger Level**: CRITICAL
- **Threats**: File encryption, Data loss, Financial extortion, System lockout

### 🕷️ RAT (6)
- **Description**: Remote Access Trojan
- **Danger Level**: HIGH
- **Threats**: Full system control, Webcam access, Data theft, Network attacks

### 🐴 Trojan (7)
- **Description**: Malware disguised as legitimate software
- **Danger Level**: HIGH
- **Threats**: Deception, Data theft, System compromise, Backdoor creation

### 🖥️ Windows System (8)
- **Description**: Legitimate Windows system files
- **Danger Level**: SAFE
- **Threats**: No threats detected

## Usage in Code

When the model returns numeric predictions, they should be converted to family names using the `reverse_label_map`:

```python
# Example conversion
numeric_prediction = 5
family_name = reverse_label_map.get(numeric_prediction, "Unknown")
# Result: "report_ransomware"
```

## Frontend Display

The frontend should display the family names with their corresponding emojis and danger levels instead of raw numbers. 