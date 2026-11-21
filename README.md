# 🛡️ SecureIT "Safe Spaces" SDK (v2.0.0 ML Production)

**An Open-Source, Localized NLP Threat Classification & Data Leakage Prevention (DLP) Engine for Nigerian EdTech Platforms and School Portals.**

Built by **SecureIT Technologies LTD (Nigeria)**, the Safe Spaces SDK protects students across emerging markets from cyber-extortion, online grooming, cyberbullying, and Personally Identifiable Information (PII) exposure in real time.

---

## 🚀 Enterprise Capabilities (v2.0.0)
* **Machine Learning Multi-Label Inference:** Powered by a **TF-IDF Character N-Gram + Logistic Regression** probability classifier trained on Standard English and **Nigerian Pidgin** threat contexts.
* **Anti-Evasion Text Normalization:** Automatically decodes obfuscated slang, leetspeak (`s3nd`), and punctuation-split evasions (`s.e.n.d`) prior to inference.
* **Nigerian PII Data Leakage Prevention:** Intercepts and redacts standard and disguised Nigerian mobile signatures (`+234`, `080-3123-4567`, `081`, `070`, `090`, `091`) in milliseconds.
* **School Admin Escalation Queue:** Built-in human-in-the-loop dashboard allowing school counselors and platform administrators to review and resolve high-risk alerts.
* **Configurable Sensitivity Modes:** Supports `strict` (Primary/Secondary), `moderate` (University), and `lenient` policy thresholds.

---

## 🛠️ Quickstart: Run the v2.0.0 Enterprise Console

1. **Clone the repository:**
   ```bash
   git clone https://github.com
   cd safespaces-sdk
   ```

2. **Install ML and API dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Launch the FastAPI server:**
   ```bash
   uvicorn app:app --reload
   ```

4. **Open the Console:**
   Navigate to `http://127.0.0.1:8000` in your browser to access both the **Live API & ML Sandbox** and the **School Admin Alert Queue**.

---

## 🗺️ 12-Month Roadmap (Open-Core Sustainability)
* **Open-Source Core (MIT License):** Free self-hosted SDK and single-portal moderation engine for underfunded Nigerian public schools and grassroots EdTech startups.
* **Commercial Enterprise Tier:** Centralized multi-tenant analytics dashboard and managed cloud API for commercial EdTech enterprises and private school networks.

---

## 📄 License
Licensed under the **MIT License** as a Global Digital Public Good.
