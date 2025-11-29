# 🔒 SIRS Project — Secure Chain of Product (CoP) Library

---

## 🛡 Project Overview

This repository contains the source code for the **Secure Document Library** developed for the course:

> **Network and Computer Security**  
> **Segurança Informática em Redes e Sistemas (SIRS)**  
> Academic Year **2025/2026**

The project addresses the challenge of maintaining **Confidentiality** and **Integrity** in a distrustful supply chain (**Chain of Product**) using a public third-party service and the **Java Cryptography Architecture (JCA/JCE)**.

---

## 📦 Scenario — Chain of Product (DvP Transaction Protection)

The system protects transaction data passing through untrusted environments using cryptography to ensure:

- Confidentiality  
- Integrity  
- Authentication  
- Secure Sharing  

---

## 👥 Team Information

**Team:**  
_[Your Team Member Names and IDs Here]_

**Primary Author:**  
**Shahnewaj Muhammad Shakil** (`ist1112011`)

---

# 🛡 Security Requirements Addressed (Stage 1 & 2)

The document protection scheme is based on **Hybrid Encryption** and **Digital Signatures** to meet security requirements.

## ✅ Requirements Table

| ID | Requirement | Cryptographic Solution | Status |
|----|------------|------------------------|--------|
| **SR1** | Confidentiality | AES-256 GCM (Data) + RSA-3072 OAEP (Key Wrap) | ✅ Implemented |
| **SR2** | Authentication | Signed Disclosure Records (Stage 5) | 🕓 Planning |
| **SR3** | Integrity 1 | SHA256withRSA Dual Signatures | ✅ Implemented |
| **SR4** | Integrity 2 | Signed Disclosure Records (Stage 5) | 🕓 Planning |

---

# 🏗 Project Structure

The project is built using:

- Java Runtime Environment (JRE)  
- Maven  
- Java Cryptography Architecture (JCA/JCE)

---

## 📂 Directory Layout

.
├── pom.xml
├── src/main/java/securitylib/
│ ├── KeyManager.java
│ ├── SecureDocumentCrypto.java
│ └── MainApp.java
├── target/
│ └── chainofproduct-cli-jar-with-dependencies.jar
└── .gitignore


---

## 📄 File Descriptions

### `pom.xml`
Defines:
- Java 17 target
- JSON dependency
- Assembly plugin for JAR packaging

---

### `KeyManager.java`
Responsible for:

- RSA-3072 key pair generation  
- AES-256 key generation  
- File I/O for key storage  

---

### `SecureDocumentCrypto.java`
Core cryptography engine implementing:

- AES/GCM encryption  
- RSA/OAEP key wrapping  
- SHA256withRSA signature & verification  

---

### `MainApp.java`
Command-line interface for:

- `protect`
- `check`
- `unprotect`

---

### `.gitignore`
Prevents accidental uploads of:

*_private.key
*.secured
/target


---

# 💻 Usage and Demonstration (Stage 2 CLI)

The project provides a **single executable JAR** for use via command line.

---

## A. Setup and Build

### Requirements
- Java 17+
- Maven

### Build the project


mvn clean package
Artifact is created in:

target/chainofproduct-cli-jar-with-dependencies.jar

B. Command Sequence Example

Lifecycle:

Identity → Protection → Verification → Decryption

1️⃣ Generate Identity (genkeys)

Creates RSA key pairs:

java -jar target/chainofproduct-cli-jar-with-dependencies.jar genkeys


Output:

seller_private.key

buyer_public.key

etc.

2️⃣ Prepare Input Data

Example file: original_transaction.json

{
  "id": 4096,
  "seller": "Ching Chong Extractions",
  "buyer": "Lays Chips",
  "product": "Indium",
  "amount": 90000000
}

3️⃣ Protect Document (SR1 & SR3)

Encrypt and sign:

java -jar target/chainofproduct-cli-jar-with-dependencies.jar protect \
  original_transaction.json \
  seller_private.key \
  buyer_public.key \
  protected_output.secured

What happens:

AES encrypts the document

RSA encrypts the AES key

Both parties digitally sign

4️⃣ Check Integrity (SR3)

Verify signatures:

java -jar target/chainofproduct-cli-jar-with-dependencies.jar check \
  protected_output.secured \
  seller_public.key \
  buyer_public.key

Expected output:
Seller Signature: ✅ YES
Buyer Signature: ✅ YES

5️⃣ Unprotect Confidentiality (SR1)

Decrypt:

java -jar target/chainofproduct-cli-jar-with-dependencies.jar unprotect \
  protected_output.secured \
  buyer_private.key \
  decrypted_output.json

Result:

decrypted_output.json contains the original plaintext document.

🔮 Future Stages — Infrastructure & Challenge
Stage 3 & 4 — Secure Infrastructure
Servers:

CoP-DB (Database)

CoP-APP (Application Server)

Security:

HTTPS (TLS) between CLI and server

TLS/SSH tunneling between application and database

Stage 5 — Security Challenge

Implementation goals:

SR2 — Authentication via Disclosure Records

SR4 — Sharing verification

Third-party integration for verification

Dynamic key distribution

✅ Project Summary

✔ Hybrid encryption
✔ RSA signatures
✔ Secure CLI
✔ Modern cryptographic standards
✔ Ready for distributed deployment

📌 This project demonstrates applied cryptography in a real-world transaction model.


---

If you want, I can also generate:

✅ GitHub badges  
✅ Architecture diagrams  
✅ Crypto process diagrams  
✅ Report-style README  
✅ Security workflow charts  

Just say the word 😊
