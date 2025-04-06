# Digital-Signature-Scheme_project

# 🛡️ Digital Signature Standard (DSS) Web Application

This is a Flask-based web application that demonstrates the **Digital Signature Standard (DSS)** using the **Digital Signature Algorithm (DSA)**. The app allows users to **sign**, **verify**, and even simulate **Man-in-the-Middle (MITM) attacks** with realistic **X.509 certificates**.

🔗 **GitHub Repository**: [Digital-Signature-Scheme_project](https://github.com/prasheelrdevadiga/Digital-Signature-Scheme_project.git)

---

## 📜 Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Technologies Used](#technologies-used)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
- [Advantages](#advantages)
- [Use Cases](#use-cases)
- [Understanding DSS and DSA](#understanding-dss-and-dsa)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [References](#references)


---

## 📖 Introduction

In an era of digital communication, ensuring the **authenticity**, **integrity**, and **non-repudiation** of data is essential. This web application is built to demonstrate how **Digital Signatures** using **DSA** help achieve these objectives.

The app includes the ability to:
- Sign and verify messages using digital signatures
- Generate X.509 certificates
- Simulate attacks such as MITM and show how verification fails

---

## ✨ Features

- ✅ Message Signing using DSA
- ✅ Signature Verification with real public key & certificate
- ✅ X.509 Certificate Generation
- ✅ MITM Attack Simulation with visible impact
- ✅ Scenario-based storytelling interface
- ✅ Highlighted signature validation status
- ✅ Tampering detection using real cryptographic checks
- ✅ Clean and responsive UI (HTML + CSS)

---

## 🛠️ Technologies Used

| Component      | Technology            |
|----------------|------------------------|
| Backend        | Python, Flask           |
| Cryptography   | `cryptography` library |
| Frontend       | HTML5, CSS3             |
| Certificates   | X.509 (self-signed)     |
| Development    | VS Code, Python 3.10+   |

---

## 📁 Project Structure

```
Digital-Signature-Scheme_project/
├── app.py
├── templates/
│   ├── index.html
│   ├── signed_details.html
│   ├── verify.html
│   ├── mitm.html
│   └── result.html
├── static/
│   └── style.css
├── requirements.txt
└── README.md
```

---

## 🖥️ Installation

```bash
# 1. Clone the repository
git clone https://github.com/prasheelrdevadiga/Digital-Signature-Scheme_project.git
cd Digital-Signature-Scheme_project

# 2. (Optional) Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. Install required packages
pip install -r requirements.txt

# 4. Run the Flask app
python app.py
```

---

## 🚀 Usage

1. Open `http://127.0.0.1:5000/` in your browser.
2. Fill in the **sender**, **receiver**, and **message**.
3. Click **Sign Message** to generate a digital signature and certificate.
4. Click **Verify Message** to validate the signature and detect tampering.
5. Optionally, simulate a **MITM Attack** to see how integrity fails.

---




## ✅ Advantages

- Ensures **message integrity** and **authenticity**
- Protects against message tampering
- Uses **real cryptographic keys**, not dummy data
- Highlights trust via **X.509 Certificates**
- Educational for students and security learners

---

## 🧠 Use Cases

- Educational demo for cybersecurity students
- Demonstration of secure communication protocols
- Awareness tool for data authentication
- Prototype for digital signature implementation

---

## 🔍 Understanding DSS and DSA

- **Digital Signature Standard (DSS)** is defined in FIPS 186-5 and specifies methods for generating and verifying digital signatures.
- **Digital Signature Algorithm (DSA)** is one such algorithm under DSS that uses modular exponentiation and discrete logarithms.

💡 [Read about DSA and DSS](https://www.geeksforgeeks.org/digital-signature-standard-dss/)

---

## 🔒 Security Considerations

- **Private Key Security**: Ensure private keys are not leaked or stored insecurely.
- **Certificate Validation**: Real-world use requires proper CA-issued certificates.
- **No Hardcoding**: App avoids dummy signatures and enforces cryptographic validation.

---

## 🙌 Contributing

We welcome contributions! If you'd like to improve the app or add features:

1. Fork the repo
2. Create a new branch: `git checkout -b feature-name`
3. Commit your changes: `git commit -am 'Add feature'`
4. Push to the branch: `git push origin feature-name`
5. Create a Pull Request

---

## 📚 References

- [Digital Signature Algorithm (DSA)](https://www.di-mgt.com.au/public-key-crypto-discrete-logs-4-dsa.html)
- [NIST FIPS DSS Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5-draft.pdf)
- [GeeksForGeeks DSS Guide](https://www.geeksforgeeks.org/digital-signature-standard-dss/)
- [Cryptography Docs](https://cryptography.io/en/latest/)

---


