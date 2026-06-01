# Phase 3 – Defensive Security

## Project Overview

This phase focuses on applying defensive security techniques to improve the security posture of the tools developed in previous phases. The project combines vulnerability assessment, secure communication, and data hiding techniques to demonstrate practical cybersecurity concepts.

---

## 1. Vulnerability Audit and Security Hardening

A comprehensive security audit was performed on the Phase 2 network security tool using the Bandit static analysis framework.

### Objectives

* Identify insecure coding practices.
* Evaluate security risks and vulnerabilities.
* Apply mitigation techniques.
* Verify improvements through rescanning.

### Vulnerabilities Addressed

* Insecure network binding (0.0.0.0 → 127.0.0.1)
* Unsafe SSH host key policies
* Command execution security issues
* Additional code review findings identified by Bandit

### Tools Used

* Bandit
* Python Static Analysis
* Manual Security Review

### Outcome

Security weaknesses were identified, documented, and mitigated. Before-and-after scans were used to verify the effectiveness of the applied fixes.

---

## 2. AES Encrypted Client-Server Communication

An encrypted communication layer was implemented using the Advanced Encryption Standard (AES) to protect messages exchanged between the client and server components.

### Objectives

* Ensure confidentiality of transmitted data.
* Prevent unauthorized reading of intercepted messages.
* Demonstrate secure communication principles.

### Implementation

* AES encryption using PyCryptodome.
* Shared secret key mechanism.
* Message encryption before transmission.
* Message decryption upon reception.
* Integrity verification using cryptographic techniques.

### Security Benefits

* Protects sensitive data during transmission.
* Reduces the risk of packet interception.
* Demonstrates practical cryptographic integration within network applications.

### Tools Used

* Python
* PyCryptodome

---

## 3. LSB Image Steganography

A steganography module was implemented to hide secret text messages inside digital images using the Least Significant Bit (LSB) technique.

### Objectives

* Conceal information within image files.
* Extract hidden messages successfully.
* Study basic steganographic methods and limitations.

### Implementation

* Embed text into image pixel data.
* Generate a stego-image containing the hidden message.
* Extract and recover the original message.
* Verify successful recovery.

### Detection Discussion

Although LSB steganography introduces minimal visual changes, hidden data may still be detected through:

* Histogram analysis
* Statistical analysis
* Image comparison techniques
* Specialized steganalysis tools

### Tools Used

* Python
* Pillow

---

## Technologies and Libraries

* Python 3
* Bandit
* PyCryptodome
* Pillow
* Paramiko
* Socket Programming

---

## Learning Outcomes

Through this phase, the project demonstrates:

* Secure software development practices.
* Vulnerability identification and remediation.
* Practical cryptographic communication.
* Data hiding and steganography techniques.
* Defensive cybersecurity methodologies.

---

## Author

**Lama Hamdan 202210399 IS**

**Shahed Alhamadin 202311479 IS**

**Memas Alshekani 202311369 IS**

University of Petra
Information and Network Security Programming
Phase 3 – Defensive Security
