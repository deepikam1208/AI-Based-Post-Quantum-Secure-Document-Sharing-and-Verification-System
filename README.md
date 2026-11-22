# AI-Based Post-Quantum Secure Document Sharing and Verification System

Combines automated **AI Document Classification** with **NIST-Standardized Post-Quantum Cryptography (PQC)** and **Authenticated AES-256-GCM** encryption. Styled with the **"Vintage Romance"** color palette (`#623245`, `#956a6a`, `#cfbab4`, `#cabfbe`, `#e8e3d2`).

---

## 🌟 Key Functional Capabilities

1. **Get Started Landing Page & Role-Based Authentication:**
   - **Landing Page (`/`):** Highlights quantum threat vulnerabilities of RSA/ECC and introduces NIST FIPS 203 & 204.
   - **Multi-Role Authentication:** Dedicated login for:
     - 👩‍🏫 **Teachers / Faculty:** Ingestion console with AI classification, department sharing, and PQC digital signing.
     - 👨‍🎓 **Students / Receivers:** Filtered inbox displaying only documents targeted to their department and semester, with live decapsulation, decryption, and tamper detection.
     - 🛡️ **Administrators:** Institutional overview, master registry, and immutable audit logs.
   - **One-Click Demo Personas:** Quick test access for `prof_sharma`, `prof_rao`, `rohan_verma`, `priya_nair`, and `admin`.

2. **Automated AI Document Classification & Department Affinity:**
   - In-RAM text extraction from PDF, DOCX, TXT, CSV, JSON, and code files (zero plaintext written to disk).
   - Scikit-learn TF-IDF Vectorizer + Logistic Regression Classifier predicting:
     - 🟢 **Public:** General notices, academic timetables, holiday calendars, syllabus.
     - 🟠 **Sensitive:** Internal assessment marks, attendance rosters, student resumes.
     - 🔴 **Critical:** Question papers, official answer keys, placement CTC offers.
   - Automatically detects and suggests the target department based on domain keywords.

3. **NIST Post-Quantum Cryptographic Pipeline:**
   - **NIST FIPS 203 (ML-KEM-768 / Kyber):** Lattice-based Key Encapsulation Mechanism.
   - **NIST FIPS 204 (ML-DSA-65 / Dilithium):** Lattice-based Digital Signature Algorithm (3,309 bytes signature).
   - **AES-256-GCM:** 256-bit symmetric cipher with 96-bit random nonce and 128-bit authentication tag.

4. **Cryptographic Performance Benchmark Engine:**
   - Side-by-side empirical performance comparison across:
     - **Classical Cryptography:** RSA-2048 / ECDSA P-256 + AES-128
     - **Hybrid Cryptography:** X25519 + ML-KEM-768 + AES-256
     - **Post-Quantum Cryptography:** ML-KEM-768 + ML-DSA-65 + AES-256-GCM
   - Measures key generation time, key encapsulation latency, digital signature time, and payload size.

5. **Public Verification Portal:**
   - External audit portal for employers, verification agencies, and partner universities to audit document authenticity without logging in.

---

## 🔐 Default Demo Accounts

| Role | Username | Password | Department & Details |
| :--- | :--- | :--- | :--- |
| **Teacher (CS)** | `prof_sharma` | `faculty123` | Department of Computer Science (HOD) |
| **Teacher (EE)** | `prof_rao` | `faculty123` | Department of Electrical Engineering |
| **Student (CS)** | `rohan_verma` | `student123` | USN: `1CS23CS045` • Computer Science • Sem 6 |
| **Student (EE)** | `priya_nair` | `student123` | USN: `1EE24EE012` • Electrical Engineering • Sem 4 |
| **Administrator** | `admin` | `admin123` | Dr. V. Raman • Controller of Examinations |

---

## 🚀 Quickstart Guide

### 1. Run the Interactive Web Server
```powershell
python server.py
```
Open your browser and navigate to:
```
http://127.0.0.1:5000
```

### 2. Run the Automated Verification Suite
```powershell
python test_system.py
```

### 3. Run Cryptographic Benchmarks Directly
```powershell
python benchmark_engine.py
```

---

## ☁️ Storage Architecture & Cloudflare Strategy

- **Plaintext:** Exists solely in volatile RAM during text parsing and is immediately purged.
- **Encrypted Files (`.enc`):** Stored in `storage/encrypted/` locally, or in **Cloudflare R2 Object Storage** in production (enjoying **zero egress bandwidth fees** and server-side encryption at rest).
- **Network Pipeline:** Transferred via **Cloudflare TLS 1.3 with Hybrid Post-Quantum Key Exchange (X25519 + Kyber)** to safeguard against "Harvest Now, Decrypt Later" adversaries.
- **Relational Metadata:** Stored in MySQL Community Server / SQLite, keeping large binaries decoupled from SQL tables.
