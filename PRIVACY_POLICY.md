# **SEMANTICSAV PLATFORM PRIVACY POLICY**

**Effective Date:** October 1, 2025  
**Last Updated:** October 1, 2025

Meta Forensics Corp. ("Company," "we," "us," or "our") is committed to protecting your privacy. This Privacy Policy explains how we collect, use, disclose, and safeguard your information when you use the SemanticsAV Platform ("Platform"). Please read this Privacy Policy carefully.

---

## **1. SCOPE OF THIS PRIVACY POLICY**

This Privacy Policy applies to the entire SemanticsAV Platform ecosystem:

- **SemanticsAV SDK**: The on-device analysis engine
- **SemanticsAV CLI**: The open-source interface for network communications
- **SemanticsAV Intelligence**: The optional cloud service for advanced analysis

For details on how each component handles your data, see Section 2 below.

---

## **2. PLATFORM ARCHITECTURE AND DATA TRANSPARENCY**

### **On-Device Analysis**

The SemanticsAV SDK performs all file analysis locally with zero network capability. The SDK contains no networking code, performs no data transmission, and cannot communicate with external servers. Files never leave your device during scanning.

### **Network Communications**

The SemanticsAV CLI (open-source, MIT-licensed) is the sole component handling network communications. The CLI downloads model updates from Company servers and, when you use Intelligence, transmits analysis requests and receives results.

**Complete transparency is guaranteed**: You can audit all data transmission by inspecting the CLI source code at https://github.com/metaforensics-ai/semantics-av-cli.

### **Cloud Intelligence (Optional)**

When using Intelligence, only a proprietary encrypted analysis payload is transmitted—never the original file. This payload is deterministic: identical files produce identical payloads with the same SDK version, enabling indirect verification through the open-source CLI.

### **Privacy by Design**

This architectural separation ensures that you maintain complete control over your data. Original files remain on your system, and all network activity occurs through auditable open-source code.

---

## **3. INFORMATION WE COLLECT**

### **3.1 SDK Usage (Offline Mode)**

When you use the SDK for local file scanning:
- **No information is collected**
- **No data is transmitted**
- Analysis occurs entirely on your device
- No network connection is required or used

### **3.2 Intelligence Service Usage (Optional Cloud Mode)**

When you choose to use Intelligence, we collect:

**a) File Identification Data:**
- Cryptographic hashes (MD5, SHA-1, SHA-256)
- File type and format classification
- File size

**b) Analysis Payload:**
- Encrypted analytical payload derived from file analysis
- Payload cannot reconstruct the original file
- Generation is deterministic and verifiable

**c) Service Usage Information:**
- API usage patterns and request frequency
- Error logs and diagnostic information
- Performance metrics

**Privacy Guarantee:** The Platform never collects, transmits, or stores the actual contents of your files. Only the encrypted analytical payload, cryptographic hashes, and metadata are processed by Intelligence.

### **3.3 Account and Service Management**

When you create an Intelligence account:

**a) Registration Information:**
- Email address and authentication credentials
- Account creation and access timestamps
- Account tier and subscription status

**b) Service Usage Data:**
- API keys and usage metrics
- Rate limit tracking
- Console access logs

**c) Billing Information:**
- Payment method and transaction data (processed by third-party payment providers)
- Billing address and invoice information
- Subscription history

For contractual terms regarding account management and lifecycle, see the Intelligence Terms of Service.

---

## **4. HOW WE USE YOUR INFORMATION**

We use collected information to:

**a) Provide Intelligence Services**
Process analysis requests and deliver threat detection results.

**b) Manage Your Account**
Create and maintain accounts, process subscriptions, handle authentication, and provide support.

**c) Improve Detection Capabilities**
Enhance algorithms, strengthen detection models, improve response times, and advance threat analysis methodologies.

**d) Maintain Service Quality**
Detect unauthorized access, ensure system stability, and maintain operational security.

**e) Comply with Legal Obligations**
Meet applicable legal requirements and respond to lawful requests.

---

## **5. LEGAL BASIS FOR PROCESSING**

Our legal basis for processing your information includes:

- **Contract Performance:** Processing necessary to fulfill obligations under the Intelligence Terms of Service
- **Legitimate Interest:** Processing necessary to provide services, improve threat detection, and maintain security
- **Legal Obligation:** Processing required to comply with applicable laws
- **Consent:** Where applicable law requires consent for specific processing activities

---

## **6. DATA RETENTION**

We retain information as necessary to provide services, comply with legal obligations, resolve disputes, enforce agreements, and fulfill legitimate business purposes.

**Active Accounts:** Account and service data retained during account lifetime.

**Terminated Accounts:** Data may be retained post-termination as specified in Intelligence Terms of Service Section 6.4, based on operational, legal, and business requirements.

**Analysis Data:** File identification and analysis data retained to improve threat detection and maintain service quality.

Specific retention periods vary based on data type and legal requirements. For account-specific policies, refer to Intelligence Terms of Service Section 6.4.

---

## **7. DATA SECURITY**

We implement comprehensive security measures to protect information against unauthorized access, alteration, disclosure, or destruction:

- End-to-end encryption for communications and data at rest
- Multi-layered access controls and authentication
- Continuous security monitoring
- Secure data processing environments
- Regular security audits

While we maintain industry-standard practices, no method of transmission or storage is completely secure. We cannot guarantee absolute security but strive to protect your data using best practices.

---

## **8. DATA SHARING AND DISCLOSURE**

We do not sell, trade, or rent your personal information to third parties. We may share information in the following circumstances:

### **a) Service Providers**

We engage trusted third-party providers to operate and enhance the Platform:

**Service Delivery:**
- Cloud infrastructure providers for hosting and data processing
- AI and machine learning service providers for intelligence report generation

**Security and Research:**
- Threat intelligence partners for collaborative malware research
- Security research organizations for detection capability advancement

**Account Management:**
- Payment processors for subscription transactions (subject to their own privacy policies)

**Data Protection Measures:**

All service providers are:
- Carefully selected based on industry-leading security and privacy standards
- Contractually bound to process data only as instructed
- Subject to strict confidentiality agreements and data protection obligations
- Granted access only to information necessary for their functions

### **b) Legal Requirements**
When required by law, regulation, legal process, or governmental request.

### **c) Security and Safety**
To protect our rights, property, or safety, or that of our users or others, including Platform security.

### **d) Business Transfers**
In connection with any merger, sale of company assets, or acquisition affecting the Platform.

---

## **9. INTERNATIONAL DATA TRANSFERS**

Your information may be processed and stored in countries other than your own as part of Platform operations, including through third-party service providers operating in different jurisdictions.

We ensure appropriate safeguards for all international data transfers in accordance with applicable data protection laws:

- Standard Contractual Clauses (SCCs) approved by relevant authorities
- Adequacy decisions by the European Commission where applicable
- Additional security measures for data in transit and at rest

You can request information about specific safeguards applied to your data by contacting privacy@metaforensics.ai.

---

## **10. YOUR RIGHTS**

Depending on your jurisdiction, you may have the following rights:

- **Access:** Request access to your personal information
- **Rectification:** Request correction of inaccurate or incomplete information
- **Erasure:** Request deletion under certain circumstances, subject to retention obligations in Section 6
- **Restriction:** Request limitation of processing under certain circumstances
- **Portability:** Request transfer of your information to another service
- **Objection:** Object to processing based on legitimate interests
- **Withdraw Consent:** Withdraw consent at any time where processing is based on consent

To exercise these rights, contact privacy@metaforensics.ai. We will respond in accordance with applicable law.

Note that certain rights may be limited by legal obligations or legitimate business needs, including retention requirements specified in Intelligence Terms of Service.

---

## **11. CHILDREN'S PRIVACY**

The Platform is not intended for individuals under the age of 13. We do not knowingly collect personal information from children under 13. If we become aware that we have collected personal information from a child under 13, we will take steps to delete such information.

---

## **12. CHANGES TO THIS PRIVACY POLICY**

We may update this Privacy Policy from time to time. We will notify you of any material changes by posting the updated Privacy Policy and updating the "Last Updated" date. Your continued use of the Platform after such changes constitutes acceptance of the updated Privacy Policy.

---

## **13. CONTACT INFORMATION**

**Privacy inquiries:**
privacy@metaforensics.ai

**Address:**
46, Mangu-ro, Dongdaemun-gu, Seoul, Republic of Korea

**Data Protection Officer (EU inquiries):**
privacy@metaforensics.ai

**Account management and support:**
support@metaforensics.ai

**GitHub Repository:**
https://github.com/metaforensics-ai/semantics-av-cli

---

**© 2025 Meta Forensics Corp. All rights reserved.**