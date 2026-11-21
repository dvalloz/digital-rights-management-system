# Digital Rights Management (DRM) Prototype System

A modular Python implementation of a Digital Rights Management (DRM) system inspired by the W3C Encrypted Media Extensions (EME) specification and modern DRM architectures (such as Widevine and FairPlay).

## System Highlights

- **Hybrid Cryptography**: Session establishment using RSA-2048 with OAEP padding, followed by high-throughput symmetric encryption using AES-128 in CBC mode with PKCS#7 padding.
- **Digital Signatures & Non-Repudiation**: License acquisition requests are signed using RSA-PSS and SHA-256 to ensure authenticity and integrity before keys are issued.
- **Dynamic Forensic Watermarking**: Real-time user watermark injection into visual media to protect against illicit redistribution.
- **Heuristic Media Inspection**: Automatic detection of AES-CBC ciphertext vs. plaintext multimedia via magic bytes analysis (JPEG, PNG, MP4) and 16-byte block boundary verification.
- **Decoupled Architecture (W3C EME Model)**:
  - **User Agent (UA)**: Application frontend managing network transfers and user interaction.
  - **Content Decryption Module (CDM)**: Isolated security component holding private keys, signing license requests, and decrypting protected media directly.
  - **Content Server**: TCP media streaming service.
  - **License Server**: Key management system (KMS) issuing symmetric keys and initialization vectors over secure channels.

## Architecture Overview

```
                      +-------------------+
                      |   Content Server  | (Port 8000)
                      +-------------------+
                             ^     |
                1. GET Media |     | 2. Protected Media + Watermark
                             |     v
+------------------+     +------------+     3. License Req      +-------------------+
|       CDM        |<--->| User Agent |------------------------>|  License Server   | (Port 9000)
| (Isolated Engine)|     |    (UA)    |<------------------------|   (KMS Service)   |
+------------------+     +------------+     4. Encrypted Keys   +-------------------+
     (Port 8002)
```

## Repository Structure

```
├── docs/                      # Technical reports and system specification
├── src/
│   ├── client/
│   │   ├── cliente.py         # Integrated client (Phases 1 & 2)
│   │   ├── ua.py              # Decoupled User Agent (Phase 3)
│   │   ├── cdm.py             # Content Decryption Module (Phase 3)
│   │   └── downloads/         # Local secure download directory
│   ├── content_server/
│   │   ├── content_server.py  # Media distribution service
│   │   └── media/             # Media repository (clear & ciphered samples)
│   ├── license_server/
│   │   ├── license_server.py  # License authority & Key store
│   │   └── keys/              # Key storage (AES keys and IVs)
│   ├── core/
│   │   ├── crypto_detect.py   # Magic bytes & block alignment inspection
│   │   ├── digital_signature.py # RSA-PSS signature & verification
│   │   └── watermark.py       # Pillow-based dynamic watermarking
│   └── tools/
│       └── ENCRIPTADOR_DE_CONTENIDO_def.py # Media pre-encryption utility
├── .gitignore
├── requirements.txt
└── README.md
```

## Quick Start

### 1. Requirements

Install required dependencies:

```bash
pip install -r requirements.txt
```

### 2. Running Services

Open three separate terminals:

**Terminal 1 - Content Server:**
```bash
python src/content_server/content_server.py
```

**Terminal 2 - License Server:**
```bash
python src/license_server/license_server.py
```

**Terminal 3 - Client:**
- For integrated mode:
  ```bash
  python src/client/cliente.py
  ```
- For decoupled mode (run CDM first, then UA):
  ```bash
  python src/client/cdm.py
  python src/client/ua.py
  ```

### Interactive Client Commands

- `LIST`: Displays available files (`all`, `.jpg`, `.mp4`).
- `GET <filename>`: Downloads the file, validates its encryption status, acquires license if needed, and decrypts the content.
- `EXIT`: Closes connection.

## Skills Demonstrated

- Applied Cryptography (AES-128-CBC, RSA-2048, OAEP, PSS, PKCS#7).
- Network Programming (TCP Sockets, custom protocols, multi-threading).
- System Architecture (W3C EME, CDM sandboxing, Zero-Trust principles).
- Digital Forensics & Steganography (Dynamic watermarking with Pillow).
