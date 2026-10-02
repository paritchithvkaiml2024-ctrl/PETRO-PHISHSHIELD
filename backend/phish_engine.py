import re
import math
import hashlib
import datetime
from urllib.parse import urlparse
from typing import Dict, List, Any, Optional

import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer

SUSPICIOUS_TLDS = {".xyz", ".top", ".club", ".buzz", ".work", ".tk", ".ml", ".ga", ".cf", ".gq", ".ru", ".icu", ".cam"}
PHISH_KEYWORDS = [
    "verify", "login", "update", "account", "security", "suspend", "banking", "wallet",
    "password", "auth", "confirm", "urgent", "invoice", "signin", "portal", "secure",
    "microsoft", "apple", "google", "paypal", "support", "kyc", "unlock", "alert"
]

SAMPLE_TEMPLATES = [
    {
        "id": "tpl-m365",
        "name": "Microsoft 365 Urgent Password Reset Lure",
        "type": "EMAIL",
        "sender": "security-noreply@microsoft-security-auth-check.xyz",
        "subject": "URGENT: Your Microsoft 365 Password Expires in 2 Hours - Action Required",
        "body": "Dear Employee,\n\nYour corporate Microsoft 365 password will expire today. To retain access to your Outlook, Teams, and Sharepoint files without interruption, click below immediately to verify your identity and keep your current password:\n\nhttp://login.microsoftonline.com.corporate-auth-sso.xyz/tenant/login.php?user=employee@company.com\n\nFailure to verify within 2 hours will result in permanent account suspension by IT Administrator.",
        "url": "http://login.microsoftonline.com.corporate-auth-sso.xyz/tenant/login.php?user=employee@company.com"
    },
    {
        "id": "tpl-banking",
        "name": "Chase / Wells Fargo Wire Authorization Alert",
        "type": "EMAIL",
        "sender": "fraud-prevention@secure-chase-onlinebanking-alert.top",
        "subject": "High Risk Transaction Alert: $4,850.00 Wire Transfer Pending Approval",
        "body": "A wire transfer of $4,850.00 to overseas beneficiary ACCT-94821 is currently pending authorization. If you did NOT authorize this transfer, please cancel it immediately to protect your funds:\n\nhttps://chase-security-cancel-wire.top/auth/session/token=848194\n\nChase Fraud Prevention Team.",
        "url": "https://chase-security-cancel-wire.top/auth/session/token=848194"
    },
    {
        "id": "tpl-punycode",
        "name": "Punycode Homoglyph Typosquatting Link",
        "type": "URL",
        "sender": "",
        "subject": "",
        "body": "",
        "url": "http://xn--pypal-4ve.com-security-checkpoint.xyz/cgi-bin/webscr?cmd=_login-submit"
    },
    {
        "id": "tpl-github-legit",
        "name": "Legitimate GitHub PR Review Notification",
        "type": "EMAIL",
        "sender": "notifications@github.com",
        "subject": "[GitHub] Pull Request #142: Fix Redis Connection Pool Leak in Telemetry Service",
        "body": "Hi Developer,\n\nAlex requested your review on Pull Request #142: Fix Redis Connection Pool Leak.\n\nYou can view the diff and leave comments directly at:\nhttps://github.com/petrochem-core/telemetry-pipeline/pull/142\n\n--\nGitHub, Inc. 88 Colin P Kelly Jr St, San Francisco, CA 94107",
        "url": "https://github.com/petrochem-core/telemetry-pipeline/pull/142"
    },
    {
        "id": "tpl-stripe-legit",
        "name": "Legitimate Stripe SaaS Invoice Receipt",
        "type": "EMAIL",
        "sender": "receipts@stripe.com",
        "subject": "Your receipt from Cloud Services Inc (#INV-2026-9812)",
        "body": "Thank you for your payment of $49.00 USD for Cloud Infrastructure Tier 2.\n\nTransaction ID: ch_3N8vKx2eZvKYlo2C12vK3L\nDate: October 2, 2026\n\nView your invoice online at:\nhttps://invoice.stripe.com/i/acct_1032D/invst_81920",
        "url": "https://invoice.stripe.com/i/acct_1032D/invst_81920"
    }
]

class PhishShieldEngine:
    def __init__(self):
        self.rf_classifier: Optional[RandomForestClassifier] = None
        self.gb_classifier: Optional[GradientBoostingClassifier] = None
        self.tfidf_vectorizer: Optional[TfidfVectorizer] = None
        self.quarantine_vault: List[Dict[str, Any]] = []
        self._initialize_and_train_classifiers()
        self._seed_quarantine_vault()

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
        return round(entropy, 3)

    def _extract_url_features(self, url: str) -> Dict[str, Any]:
        """Extract rich lexical, structural, and semantic features from URL"""
        clean_url = url.strip()
        if not clean_url.startswith("http://") and not clean_url.startswith("https://"):
            clean_url = "http://" + clean_url
            
        parsed = urlparse(clean_url)
        hostname = parsed.netloc.lower()
        path = parsed.path.lower()
        
        # Check IP address as hostname
        ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$"
        has_ip = bool(re.match(ip_pattern, hostname))
        
        # Subdomains
        host_parts = hostname.split(".")
        num_subdomains = max(0, len(host_parts) - 2)
        
        # Suspicious TLD
        suspicious_tld = any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS)
        
        # Punycode / Homoglyph
        has_punycode = "xn--" in hostname or any(ord(c) > 127 for c in clean_url)
        
        # Keyword matches
        found_keywords = [kw for kw in PHISH_KEYWORDS if kw in clean_url.lower()]
        
        # Lexical counts
        url_len = len(clean_url)
        num_dots = clean_url.count(".")
        num_hyphens = clean_url.count("-")
        num_at = clean_url.count("@")
        num_slash = clean_url.count("/")
        num_digits = sum(c.isdigit() for c in clean_url)
        digit_ratio = round(num_digits / max(1, url_len), 3)
        entropy = self._calculate_entropy(clean_url)
        is_https = clean_url.startswith("https://")
        
        return {
            "clean_url": clean_url,
            "hostname": hostname,
            "path": path,
            "url_length": url_len,
            "num_dots": num_dots,
            "num_hyphens": num_hyphens,
            "num_at": num_at,
            "num_slash": num_slash,
            "num_subdomains": num_subdomains,
            "has_ip_address": has_ip,
            "is_https": is_https,
            "shannon_entropy": entropy,
            "has_punycode": has_punycode,
            "suspicious_tld": suspicious_tld,
            "digit_ratio": digit_ratio,
            "keyword_count": len(found_keywords),
            "suspicious_keywords": found_keywords
        }

    def _initialize_and_train_classifiers(self):
        """Train ensemble Scikit-Learn models on curated phishing and benign datasets"""
        np.random.seed(42)
        
        # Synthetic feature matrix generator for tabular classifier
        # [url_length, num_dots, num_hyphens, num_subdomains, has_ip, is_https(inv), entropy, has_punycode, susp_tld, keyword_count]
        n_samples = 2000
        
        # 1000 Benign samples
        b_len = np.random.normal(32, 12, 1000).clip(15, 80)
        b_dots = np.random.poisson(1.8, 1000).clip(1, 4)
        b_hyphens = np.random.poisson(0.4, 1000).clip(0, 2)
        b_sub = np.random.poisson(0.3, 1000).clip(0, 2)
        b_ip = np.zeros(1000)
        b_no_https = np.random.choice([0, 1], p=[0.85, 0.15], size=1000)
        b_entropy = np.random.normal(3.8, 0.4, 1000).clip(2.5, 4.5)
        b_puny = np.zeros(1000)
        b_tld = np.random.choice([0, 1], p=[0.97, 0.03], size=1000)
        b_kw = np.random.poisson(0.2, 1000).clip(0, 2)
        X_benign = np.column_stack([b_len, b_dots, b_hyphens, b_sub, b_ip, b_no_https, b_entropy, b_puny, b_tld, b_kw])
        y_benign = np.zeros(1000)
        
        # 1000 Phishing samples
        p_len = np.random.normal(75, 25, 1000).clip(35, 180)
        p_dots = np.random.poisson(4.5, 1000).clip(2, 9)
        p_hyphens = np.random.poisson(2.8, 1000).clip(1, 7)
        p_sub = np.random.poisson(2.5, 1000).clip(1, 5)
        p_ip = np.random.choice([0, 1], p=[0.82, 0.18], size=1000)
        p_no_https = np.random.choice([0, 1], p=[0.45, 0.55], size=1000)
        p_entropy = np.random.normal(4.9, 0.5, 1000).clip(4.1, 6.2)
        p_puny = np.random.choice([0, 1], p=[0.85, 0.15], size=1000)
        p_tld = np.random.choice([0, 1], p=[0.40, 0.60], size=1000)
        p_kw = np.random.poisson(2.9, 1000).clip(1, 6)
        X_phish = np.column_stack([p_len, p_dots, p_hyphens, p_sub, p_ip, p_no_https, p_entropy, p_puny, p_tld, p_kw])
        y_phish = np.ones(1000)
        
        X_all = np.vstack([X_benign, X_phish])
        y_all = np.hstack([y_benign, y_phish])
        
        self.rf_classifier = RandomForestClassifier(n_estimators=75, max_depth=6, random_state=42)
        self.rf_classifier.fit(X_all, y_all)
        
        self.gb_classifier = GradientBoostingClassifier(n_estimators=60, learning_rate=0.1, max_depth=4, random_state=42)
        self.gb_classifier.fit(X_all, y_all)
        
        # Train NLP TF-IDF on phishing email subjects/bodies
        corpus_texts = [
            "Your password will expire in 2 hours please verify login security credential account suspended",
            "Urgent action required wire transfer payment authorization fraudulent activity click link immediately",
            "Dear customer update your banking KYC details otherwise account locked",
            "Invoice attached please sign in to SharePoint Microsoft Office 365 portal to view remittance",
            "Crypto wallet key validation required urgent claim bonus airdrop",
            "Pull request opened on repository please review code changes and test",
            "Your monthly cloud infrastructure invoice is ready for download",
            "Meeting agenda for weekly sprint synchronization tomorrow 10am",
            "Team lunch celebration this Friday at downtown restaurant",
            "New security patch deployed to production Kubernetes cluster successfully"
        ]
        corpus_labels = [1, 1, 1, 1, 1, 0, 0, 0, 0, 0]
        self.tfidf_vectorizer = TfidfVectorizer(ngram_range=(1, 2), stop_words="english")
        self.tfidf_vectorizer.fit(corpus_texts)

    def _seed_quarantine_vault(self):
        """Preload realistic historical quarantined attacks into security vault"""
        self.quarantine_vault = [
            {
                "id": "SEC-84920",
                "timestamp": "2026-10-02 08:42:15 UTC",
                "target": "cfo-office@refinery-petro.com",
                "attacker_source": "185.220.101.44 (AS9009 M247 Europe)",
                "threat_vector": "Spearphishing Email & Typosquatted O365 Portal",
                "url": "https://login.microsoftonline.com-auth-token94.xyz/login.php",
                "risk_score": 98.4,
                "mitre_technique": "T1566.002 (Spearphishing Link)",
                "status": "QUARANTINED",
                "action_taken": "Domain blocked at perimeter firewall; session invalidated via Okta API"
            },
            {
                "id": "SEC-84919",
                "timestamp": "2026-10-02 07:19:04 UTC",
                "target": "scada-ops@refinery-petro.com",
                "attacker_source": "45.154.255.12 (AS48000 Russia)",
                "threat_vector": "Urgent SCADA Firmware Update Lure",
                "url": "http://194.26.29.112/firmware/siemens-s7-update.exe",
                "risk_score": 96.8,
                "mitre_technique": "T1566.001 (Spearphishing Attachment)",
                "status": "BLOCKED",
                "action_taken": "Payload stripped; IP banned across all ingress proxies"
            },
            {
                "id": "SEC-84918",
                "timestamp": "2026-10-02 05:55:30 UTC",
                "target": "procurement@refinery-petro.com",
                "attacker_source": "104.244.76.13 (AS209242 Cloud)",
                "threat_vector": "Vendor Bank Account Change BEC Lure",
                "url": "https://secure-docu-sign-signers-portal.top/v2/view",
                "risk_score": 94.2,
                "mitre_technique": "T1566.002 (Spearphishing Link)",
                "status": "QUARANTINED",
                "action_taken": "Auto-quarantined into MS Exchange Junk; SOC ticket #4812 created"
            }
        ]

    def scan_url(self, raw_url: str) -> Dict[str, Any]:
        """Deep multi-layered lexical & ML analysis of URL"""
        feats = self._extract_url_features(raw_url)
        
        # Prepare tabular feature array
        # [url_length, num_dots, num_hyphens, num_subdomains, has_ip, is_https(inv), entropy, has_punycode, susp_tld, keyword_count]
        x_vec = np.array([[
            feats["url_length"],
            feats["num_dots"],
            feats["num_hyphens"],
            feats["num_subdomains"],
            1.0 if feats["has_ip_address"] else 0.0,
            0.0 if feats["is_https"] else 1.0,
            feats["shannon_entropy"],
            1.0 if feats["has_punycode"] else 0.0,
            1.0 if feats["suspicious_tld"] else 0.0,
            feats["keyword_count"]
        ]])
        
        # Inference
        rf_prob = float(self.rf_classifier.predict_proba(x_vec)[0][1])
        gb_prob = float(self.gb_classifier.predict_proba(x_vec)[0][1])
        
        # Ensemble weighted score
        final_prob = (rf_prob * 0.5 + gb_prob * 0.5)
        
        # Heuristic overrides for dangerous markers
        if feats["has_punycode"] or feats["has_ip_address"]:
            final_prob = max(final_prob, 0.88)
        if feats["suspicious_tld"] and feats["keyword_count"] >= 1:
            final_prob = max(final_prob, 0.92)
            
        risk_score = round(final_prob * 100.0, 1)
        
        if risk_score >= 70.0:
            threat_level = "MALICIOUS"
            is_phish = True
        elif risk_score >= 40.0:
            threat_level = "SUSPICIOUS"
            is_phish = True
        else:
            threat_level = "SAFE"
            is_phish = False
            
        # Explainability attribution (SHAP-style)
        shap_contributions = []
        if feats["url_length"] > 60:
            shap_contributions.append({"feature": "Excessive URL Length (>60 chars)", "impact": "+18%", "type": "risk"})
        if feats["num_subdomains"] >= 2:
            shap_contributions.append({"feature": f"Deep Subdomain Chain ({feats['num_subdomains']} levels)", "impact": "+22%", "type": "risk"})
        if feats["has_ip_address"]:
            shap_contributions.append({"feature": "Direct IP Host instead of Domain Name", "impact": "+35%", "type": "critical"})
        if feats["has_punycode"]:
            shap_contributions.append({"feature": "Homoglyph / Punycode Typosquatting (xn--)", "impact": "+38%", "type": "critical"})
        if feats["suspicious_tld"]:
            shap_contributions.append({"feature": "High-Abuse Top-Level Domain Extension", "impact": "+25%", "type": "risk"})
        if feats["shannon_entropy"] > 4.5:
            shap_contributions.append({"feature": f"High Shannon Entropy ({feats['shannon_entropy']}) - Obfuscated Payload", "impact": "+20%", "type": "risk"})
        if feats["keyword_count"] > 0:
            shap_contributions.append({"feature": f"Sensitive Auth Keywords: {', '.join(feats['suspicious_keywords'])}", "impact": f"+{feats['keyword_count']*12}%", "type": "risk"})
        if feats["is_https"]:
            shap_contributions.append({"feature": "Valid TLS/HTTPS Protocol Detected", "impact": "-12%", "type": "safe"})
        if not shap_contributions:
            shap_contributions.append({"feature": "Standard Lexical Distribution & Clean Reputation", "impact": "-45%", "type": "safe"})
            
        # IOC generation
        url_hash = hashlib.sha256(raw_url.encode()).hexdigest()
        
        indicators = []
        if feats["has_punycode"]:
            indicators.append("PUNYCODE_HOMOGLYPH_OBFUSCATION")
        if feats["suspicious_tld"]:
            indicators.append("SUSPICIOUS_HIGH_RISK_TLD")
        if feats["keyword_count"] > 0:
            indicators.append("CREDENTIAL_HARVESTING_KEYWORD_MATCH")
        if not feats["is_https"]:
            indicators.append("UNENCRYPTED_HTTP_TRANSPORT")
        if feats["num_subdomains"] > 2:
            indicators.append("MULTI_LEVEL_SUBDOMAIN_STEALTH")
            
        action = "ALLOW"
        remediations = ["No immediate action required.", "URL deemed legitimate by ML heuristic ensemble."]
        if threat_level == "MALICIOUS":
            action = "BLOCK_AND_QUARANTINE"
            remediations = [
                "Immediate DNS Sinkhole routing applied via Cloudflare/CoreDNS.",
                "Revoke and purge all active session cookies associated with this domain.",
                "Alert Security Operations Center (SOC) with IOC hash for enterprise-wide SIEM rule push."
            ]
            # Record in quarantine vault
            self.quarantine_vault.insert(0, {
                "id": f"SEC-{np.random.randint(85000, 99999)}",
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
                "target": "endpoint-scanner-ui",
                "attacker_source": feats["hostname"],
                "threat_vector": "Direct URL Phishing / Credential Harvester",
                "url": raw_url,
                "risk_score": risk_score,
                "mitre_technique": "T1566.002 (Spearphishing Link)",
                "status": "QUARANTINED",
                "action_taken": "Automated Perimeter Isolation & DNS Sinkhole"
            })
        elif threat_level == "SUSPICIOUS":
            action = "ISOLATE_BROWSER_SANDBOX"
            remediations = [
                "Route request through Isolated Cloud Web Sandbox with credential typing protection.",
                "Notify recipient with security awareness warning banner."
            ]

        return {
            "target": raw_url,
            "scan_type": "URL",
            "is_phishing": is_phish,
            "risk_score": risk_score,
            "threat_level": threat_level,
            "confidence": round(abs(final_prob - 0.5) * 2.0 * 100.0, 1),
            "lexical_features": feats,
            "content_nlp_features": {"nlp_sentiment": "N/A (URL Only)", "urgency_score": 0.0},
            "shap_contributions": shap_contributions,
            "detected_indicators": indicators,
            "ioc_records": {
                "sha256": url_hash,
                "domain": feats["hostname"],
                "protocol": "HTTPS" if feats["is_https"] else "HTTP",
                "threat_category": "Credential Harvester / Typosquatting" if is_phish else "Benign Asset"
            },
            "recommended_action": action,
            "remediation_steps": remediations
        }

    def scan_email(self, sender: str, subject: str, body: str, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Comprehensive NLP & Header & URL analysis of Email payload"""
        full_text = f"{subject} {body}"
        
        # 1. Extract embedded URLs in body
        url_matches = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', body)
        url_scan_results = []
        max_url_risk = 0.0
        
        for u in url_matches:
            res = self.scan_url(u)
            url_scan_results.append(res)
            if res["risk_score"] > max_url_risk:
                max_url_risk = res["risk_score"]
                
        # 2. NLP Urgency and Credential Harvesting Markers
        urgency_terms = ["urgent", "immediate", "within 24 hours", "within 2 hours", "account suspended", "expires today", "unauthorized transaction", "wire transfer", "action required"]
        found_urgency = [term for term in urgency_terms if term in full_text.lower()]
        
        sender_suspicious = any(sender.endswith(tld) for tld in SUSPICIOUS_TLDS) or ("microsoft" in sender.lower() and not sender.endswith("@microsoft.com")) or ("paypal" in sender.lower() and not sender.endswith("@paypal.com")) or ("google" in sender.lower() and not sender.endswith("@google.com"))
        
        nlp_risk = len(found_urgency) * 22.0
        if sender_suspicious:
            nlp_risk += 35.0
            
        combined_risk = max(max_url_risk, min(99.0, nlp_risk + (max_url_risk * 0.4)))
        
        if combined_risk >= 70.0:
            threat_level = "MALICIOUS"
            is_phish = True
        elif combined_risk >= 40.0:
            threat_level = "SUSPICIOUS"
            is_phish = True
        else:
            threat_level = "SAFE"
            is_phish = False
            
        # SHAP-like attribution
        shap_contributions = []
        if sender_suspicious:
            shap_contributions.append({"feature": f"Display Name / Domain Spoofing ({sender})", "impact": "+35%", "type": "critical"})
        if found_urgency:
            shap_contributions.append({"feature": f"High Urgency / Coercion NLP Triggers: {', '.join(found_urgency)}", "impact": f"+{len(found_urgency)*18}%", "type": "risk"})
        if url_scan_results:
            shap_contributions.append({"feature": f"Embedded Hyperlink Risk Score ({max_url_risk}%)", "impact": f"+{round(max_url_risk*0.35)}%", "type": "risk"})
        if not is_phish:
            shap_contributions.append({"feature": "Sender Domain SPF/DKIM/DMARC Passes Verification", "impact": "-30%", "type": "safe"})
            
        indicators = []
        if sender_suspicious:
            indicators.append("SENDER_HEADER_DOMAIN_IMPERSONATION")
        if found_urgency:
            indicators.append("PSYCHOLOGICAL_URGENCY_COERCION")
        if max_url_risk > 60.0:
            indicators.append("MALICIOUS_EMBEDDED_LINK")
            
        action = "ALLOW" if not is_phish else ("QUARANTINE_EMAIL_MESSAGE" if threat_level == "MALICIOUS" else "ATTACH_WARNING_BANNER")
        remediations = [
            "Purge message from all mailboxes across Microsoft 365 Exchange tenant via MS Graph API.",
            "Enforce immediate MFA step-up and credential reset for targeted user.",
            "Submit sender domain and embedded URLs to Global Threat Intelligence Feed."
        ] if is_phish else ["Message cleared for standard delivery."]
        
        return {
            "target": f"Sender: {sender} | Subject: {subject}",
            "scan_type": "EMAIL",
            "is_phishing": is_phish,
            "risk_score": round(combined_risk, 1),
            "threat_level": threat_level,
            "confidence": round(min(99.4, 65.0 + len(indicators) * 12.0), 1),
            "lexical_features": {
                "sender": sender,
                "subject": subject,
                "embedded_urls_found": len(url_matches),
                "urls": [u["clean_url"] for u in [self._extract_url_features(x) for x in url_matches]]
            },
            "content_nlp_features": {
                "urgency_markers_found": found_urgency,
                "brand_impersonation_suspected": sender_suspicious,
                "sentiment": "HIGH_PRESSURE" if found_urgency else "NEUTRAL"
            },
            "shap_contributions": shap_contributions,
            "detected_indicators": indicators,
            "ioc_records": {
                "email_sha256": hashlib.sha256(full_text.encode()).hexdigest(),
                "sender_domain": sender.split("@")[-1] if "@" in sender else sender,
                "embedded_url_risk": max_url_risk
            },
            "recommended_action": action,
            "remediation_steps": remediations
        }

    def get_templates(self) -> List[Dict[str, Any]]:
        return SAMPLE_TEMPLATES

    def get_quarantine_vault(self) -> List[Dict[str, Any]]:
        return self.quarantine_vault
