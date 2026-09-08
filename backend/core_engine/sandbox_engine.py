import time
import logging
import re
import concurrent.futures
from datetime import datetime
from typing import Dict, Any, Tuple
from urllib.parse import urlparse, urljoin

import tldextract
import whois

# Using Selenium for the custom headless browser sandbox
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.common.exceptions import TimeoutException, WebDriverException
from selenium_stealth import stealth

logger = logging.getLogger(__name__)

# Known exfiltration endpoints used by phishers/infostealers
SUSPICIOUS_EXFILTRATION_HOSTS = [
    'api.telegram.org',
    'discord.com',
    'discordapp.com',
    'formspree.io',
    'formcarry.com',
    'emailjs.com',
    'webtooid.com',
    'pastebin.com'
]

# High-value targeted brands and their authorized domain roots
TARGETED_BRANDS = {
    "microsoft": {
        "keywords": ["microsoft", "office 365", "outlook", "onedrive", "sharepoint", "azure"],
        "allowed_domains": ["microsoft.com", "live.com", "office.com", "office365.com", "microsoftonline.com", "windows.net", "sharepoint.com", "aka.ms", "msft.it"]
    },
    "google": {
        "keywords": ["google", "gmail", "google drive", "google workspace", "google forms", "google docs"],
        "allowed_domains": [
            "google.com", "gmail.com", "google.co.in", "accounts.google.com",
            "forms.gle", "docs.google.com", "drive.google.com", "forms.google.com",
            "goo.gl", "g.co", "youtube.com", "youtu.be"
        ]
    },
    "paypal": {
        "keywords": ["paypal", "paypal security"],
        "allowed_domains": ["paypal.com", "paypal.me", "paypal-communication.com"]
    },
    "amazon": {
        "keywords": ["amazon", "amazon prime", "aws"],
        "allowed_domains": ["amazon.com", "amazon.in", "amazon.co.uk", "amzn.to", "aws.amazon.com"]
    },
    "apple": {
        "keywords": ["apple id", "icloud", "apple support"],
        "allowed_domains": ["apple.com", "icloud.com", "apple.co"]
    },
    "netflix": {
        "keywords": ["netflix", "netflix member"],
        "allowed_domains": ["netflix.com"]
    },
    "state_bank_of_india": {
        "keywords": ["state bank of india", "onlinesbi", "sbi yono"],
        "allowed_domains": ["onlinesbi.sbi", "sbi.co.in"]
    },
    "hdfc": {
        "keywords": ["hdfc bank", "netbanking hdfc"],
        "allowed_domains": ["hdfcbank.com"]
    },
    "dhl": {
        "keywords": ["dhl express", "dhl parcel", "dhl tracking"],
        "allowed_domains": ["dhl.com", "dhl.de"]
    },
    "chatgpt": {
        "keywords": ["chatgpt", "openai", "chatgpt plus"],
        "allowed_domains": ["openai.com", "chatgpt.com"]
    }
}

def detect_brand_impersonation(driver, current_url: str) -> dict:
    """
    Detects if an unknown domain claims the identity of a known high-value brand
    in its DOM metadata while running on unauthorized infrastructure.
    """
    result = {
        "brand_impersonation": 0,
        "impersonated_brand": None,
        "confidence": 0
    }
    
    try:
        # Extract the registered domain of the current live URL
        extracted = tldextract.extract(current_url)
        current_registered_domain = f"{extracted.domain}.{extracted.suffix}".lower()
        
        # Collect page textual identity clues
        page_title = (driver.title or "").lower()
        
        # Collect meta tags
        meta_tags_text = ""
        metas = driver.find_elements(By.XPATH, "//meta[@property='og:title' or @property='og:site_name' or @name='application-name']")
        for m in metas:
            content = m.get_attribute("content")
            if content:
                meta_tags_text += " " + content.lower()
                
        combined_identity_text = f"{page_title} {meta_tags_text}"
        
        # Compare against targeted brands
        for brand, data in TARGETED_BRANDS.items():
            for keyword in data["keywords"]:
                if keyword in combined_identity_text:
                    # Brand claimed in DOM. Check if current domain is authorized:
                    is_authorized = any(
                        current_registered_domain == allowed or current_registered_domain.endswith("." + allowed)
                        for allowed in data["allowed_domains"]
                    )
                    
                    if not is_authorized:
                        result["brand_impersonation"] = 1
                        result["impersonated_brand"] = brand
                        result["confidence"] = 95
                        print(f"   🚨 Brand Impersonation Detected! Claiming '{brand}' on unauthorized domain '{current_registered_domain}'")
                        return result
                        
    except Exception as e:
        # Graceful fallback: do not crash if DOM extraction fails
        print(f"[!] Warning during brand impersonation check: {e}")
        
    return result

class VirtualSandboxAnalyzer:
    """
    Tier 3: Custom Zero-Day Virtual Sandbox (Headless Browser).
    Spins up an isolated, stealth headless browser environment, navigates to the URL, 
    and inspects DOM, Network, Form destinations, and WHOIS lifecycle.
    """
    def __init__(self):
        # Configure Headless Chrome with anti-bot stealth options
        self.chrome_options = Options()
        self.chrome_options.add_argument("--headless=new")
        self.chrome_options.add_argument("--disable-gpu")
        self.chrome_options.add_argument("--no-sandbox")
        self.chrome_options.add_argument("--disable-dev-shm-usage")
        # Strip automation blink features
        self.chrome_options.add_argument("--disable-blink-features=AutomationControlled")
        
        # Real-world Windows 11 Chrome User-Agent header
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        self.chrome_options.add_argument(f"user-agent={self.user_agent}")

    def _query_domain_age(self, url: str) -> Tuple[int, int, int]:
        """
        Queries WHOIS data with a strict 3-second timeout.
        Returns: (domain_age_days, newly_registered_domain_flag, domain_risk_score)
        """
        try:
            ext = tldextract.extract(url)
            reg_domain = ext.registered_domain
            if not reg_domain:
                return -1, 0, 0
                
            def _fetch_whois():
                w = whois.whois(reg_domain)
                creation_date = w.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                return creation_date

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(_fetch_whois)
                creation_date = future.result(timeout=3.0)

            if creation_date and isinstance(creation_date, datetime):
                now = datetime.now(creation_date.tzinfo) if creation_date.tzinfo else datetime.now()
                age_days = (now - creation_date).days
                if age_days < 0:
                    age_days = 0
                    
                if age_days < 14:
                    print(f"   🚨 Zero-Day Scam Domain Detected! Registered {age_days} days ago (< 14 days)")
                    return age_days, 1, 90
                elif age_days < 30:
                    print(f"   ⚠️ Newly Registered Domain Detected! Registered {age_days} days ago (< 30 days)")
                    return age_days, 1, 60
                else:
                    return age_days, 0, 0
        except concurrent.futures.TimeoutError:
            print("   ℹ️ WHOIS query timed out (3s). Proceeding with behavioral analysis.")
        except Exception as e:
            print(f"   ℹ️ WHOIS query failed ({str(e)}). Proceeding with behavioral analysis.")
            
        return -1, 0, 0

    def analyze_link_in_sandbox(self, url: str) -> Dict[str, Any]:
        """
        Detonates the URL in the local headless sandbox and extracts behavioral features.
        """
        print(f"📦 [CUSTOM SANDBOX] Detonating URL in isolated stealth browser: {url}")
        
        features = {
            "sandbox_has_password_field": 0,
            "external_form_action": 0,
            "suspicious_exfiltration": 0,
            "domain_age_days": -1,
            "newly_registered_domain": 0,
            "domain_risk_score": 0,
            "brand_impersonation": 0,
            "impersonated_brand": None,
            "sandbox_brand_impersonation": 0,
            "sandbox_impersonated_brand": None,
            "detected_target_brand": "",
            "sandbox_num_redirects": 0,
            "sandbox_hidden_iframes": 0,
            "sandbox_title_mismatch": 0,
            "sandbox_unreachable": 0,
            "sandbox_threat_score": 0
        }
        
        # 1. Feature 3: Domain Age & Lifecycle Check (WHOIS)
        age_days, new_domain_flag, domain_risk = self._query_domain_age(url)
        features['domain_age_days'] = age_days
        features['newly_registered_domain'] = new_domain_flag
        features['domain_risk_score'] = domain_risk
        
        driver = None
        try:
            # 2. Initialize the Stealth Sandbox Browser
            driver = webdriver.Chrome(options=self.chrome_options)
            driver.set_page_load_timeout(6)
            driver.set_script_timeout(5)
            
            # Feature 1: Strip navigator.webdriver via CDP script before any page script executes
            driver.execute_cdp_cmd(
                "Page.addScriptToEvaluateOnNewDocument",
                {
                    "source": """
                        Object.defineProperty(navigator, 'webdriver', {
                            get: () => undefined
                        });
                        window.chrome = {
                            runtime: {}
                        };
                        Object.defineProperty(navigator, 'plugins', {
                            get: () => [1, 2, 3, 4, 5]
                        });
                        Object.defineProperty(navigator, 'languages', {
                            get: () => ['en-US', 'en']
                        });
                    """
                }
            )
            
            # Apply selenium-stealth parameters
            try:
                stealth(
                    driver,
                    languages=["en-US", "en"],
                    vendor="Google Inc.",
                    platform="Win32",
                    webgl_vendor="Intel Inc.",
                    renderer="Intel Iris OpenGL Engine",
                    fix_hairline=True,
                )
            except Exception as e:
                logger.debug(f"selenium-stealth warning: {e}")
            
            # 3. Record initial state and navigate
            initial_url = url
            driver.get(url)
            time.sleep(2) # Wait for JS dynamic SPAs / payloads to execute
            
            final_url = driver.current_url
            current_ext = tldextract.extract(final_url)
            current_reg_domain = current_ext.registered_domain.lower()
            initial_ext = tldextract.extract(initial_url)
            initial_reg_domain = initial_ext.registered_domain.lower()
            
            # Check if live page or source belongs to verified global tech ecosystems
            from .link_threat_pipeline import GLOBAL_CLEAN_DOMAINS
            is_trusted_auth_domain = current_reg_domain in GLOBAL_CLEAN_DOMAINS
            
            # 4. Feature Extraction: Redirects (Ignore standard OAuth/SSO login redirects)
            if initial_url.lower().strip('/') != final_url.lower().strip('/'):
                if initial_reg_domain in GLOBAL_CLEAN_DOMAINS and current_reg_domain in GLOBAL_CLEAN_DOMAINS:
                    print(f"   ℹ️ Legitimate SSO / OAuth redirect: {initial_reg_domain} -> {current_reg_domain}")
                    features['sandbox_num_redirects'] = 0
                else:
                    print(f"   ⚠️ Redirect detected: {initial_url} -> {final_url}")
                    features['sandbox_num_redirects'] = 1
                
            # 5. Feature Extraction: Password Harvesting Detection
            password_inputs = driver.find_elements(By.XPATH, "//input[@type='password']")
            if len(password_inputs) > 0:
                if is_trusted_auth_domain:
                    print(f"   ℹ️ Verified Official SSO Login Form on {current_reg_domain} (Legitimate Authentication)")
                    features['sandbox_has_password_field'] = 0
                else:
                    print("   🚨 Credential Harvesting Form Detected!")
                    features['sandbox_has_password_field'] = 1
                
            # 6. Feature 2: Form Exfiltration Destination Inspection
            forms = driver.find_elements(By.TAG_NAME, "form")
            for form in forms:
                form_has_sensitive_fields = False
                try:
                    # Check if this form contains password, email, or user credentials
                    pwds = form.find_elements(By.XPATH, ".//input[@type='password']")
                    emails = form.find_elements(By.XPATH, ".//input[@type='email' or contains(@name, 'user') or contains(@name, 'login') or contains(@name, 'pass')]")
                    if len(pwds) > 0 or len(emails) > 0:
                        form_has_sensitive_fields = True
                except Exception:
                    pass
                
                action_attr = form.get_attribute("action") or ""
                if action_attr.strip():
                    resolved_action = urljoin(final_url, action_attr).strip()
                    action_ext = tldextract.extract(resolved_action)
                    action_reg_domain = action_ext.registered_domain.lower()
                    
                    # Check 1: Action submits to a different registered domain
                    if action_reg_domain and current_reg_domain and action_reg_domain != current_reg_domain:
                        # Allow internal ecosystem cross-submissions (e.g. forms.gle -> google.com)
                        if is_trusted_auth_domain and action_reg_domain in GLOBAL_CLEAN_DOMAINS:
                            print(f"   ℹ️ Internal ecosystem form routing: {current_reg_domain} -> {action_reg_domain}")
                        else:
                            print(f"   🚨 External Form Action Detected! Current: {current_reg_domain} -> Submits to: {action_reg_domain}")
                            features['external_form_action'] = 1
                    
                    # Check 2: Action targets known exfiltration channels or raw IPs
                    is_suspicious_endpoint = any(host in resolved_action.lower() for host in SUSPICIOUS_EXFILTRATION_HOSTS)
                    is_raw_ip = bool(re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', resolved_action))
                    is_insecure_http = final_url.startswith("https://") and resolved_action.startswith("http://")
                    
                    if is_suspicious_endpoint or is_raw_ip or is_insecure_http:
                        print(f"   🚨 Malicious Form Exfiltration Endpoint Detected: {resolved_action}")
                        features['suspicious_exfiltration'] = 1
                        
            # 7. Feature Extraction: Hidden Iframes (Clickjacking / silent downloads)
            iframes = driver.find_elements(By.TAG_NAME, "iframe")
            hidden_iframes = 0
            for iframe in iframes:
                try:
                    size = iframe.size
                    if size['width'] <= 1 and size['height'] <= 1:
                        hidden_iframes += 1
                except Exception:
                    pass
            features['sandbox_hidden_iframes'] = hidden_iframes
            if hidden_iframes > 0:
                print(f"   ⚠️ Hidden iframes detected: {hidden_iframes}")
                
            # 8. Feature Extraction: Title & Brand Mismatch
            page_title = driver.title.lower()
            domain = urlparse(final_url).netloc.lower()
            
            known_financial_brands = ['paypal', 'bank', 'login', 'secure', 'amazon', 'microsoft', 'apple', 'netflix', 'outlook']
            for brand in known_financial_brands:
                if brand in page_title and brand not in domain:
                    print(f"   🚨 Title Mismatch! Title claims '{brand}' but domain is '{domain}'")
                    features['sandbox_title_mismatch'] = 1
                    break

            # Feature 4: Brand Impersonation Check (Metadata Cross-Verification)
            brand_info = detect_brand_impersonation(driver, final_url)
            features['brand_impersonation'] = brand_info.get("brand_impersonation", 0)
            features['impersonated_brand'] = brand_info.get("impersonated_brand")
            features['sandbox_brand_impersonation'] = brand_info.get("brand_impersonation", 0)
            features['sandbox_impersonated_brand'] = brand_info.get("impersonated_brand")
            features['detected_target_brand'] = brand_info.get("impersonated_brand") or ""
                    
            # 9. Calculate internal Sandbox Threat Score
            if is_trusted_auth_domain and not features['suspicious_exfiltration']:
                threat_score = 0
            else:
                threat_score = 0
                is_credential_risk = (
                    features['brand_impersonation'] or
                    features['external_form_action'] or
                    features['suspicious_exfiltration'] or
                    features['newly_registered_domain'] or
                    features['sandbox_title_mismatch']
                )
                if features['sandbox_has_password_field'] and is_credential_risk:
                    threat_score += 45
                if features['external_form_action']: threat_score += 40
                if features['suspicious_exfiltration']: threat_score += 55
                if features['brand_impersonation']: threat_score += 50
                if features['newly_registered_domain']: threat_score += 35
                if features['sandbox_title_mismatch']: threat_score += 30
                if features['sandbox_num_redirects']: threat_score += 20
                if features['sandbox_hidden_iframes'] > 0: threat_score += 25
            
            features['sandbox_threat_score'] = min(100, threat_score)
            
            print(f"✅ [CUSTOM SANDBOX] Analysis Complete. Sandbox Score: {features['sandbox_threat_score']}")
            return features
            
        except TimeoutException:
            print("❌ [SANDBOX] URL timed out (common for dead or evasive phishing links).")
            features['sandbox_threat_score'] = 50
            features['sandbox_unreachable'] = 1
            features['sandbox_error'] = "TIMEOUT"
            return features
        except WebDriverException as e:
            err_msg = str(e)
            print(f"❌ [SANDBOX] Browser Error: {err_msg}")
            features['sandbox_unreachable'] = 1
            if 'ERR_NAME_NOT_RESOLVED' in err_msg or 'dns' in err_msg.lower():
                print("   ⚠️ Domain failed DNS resolution (ERR_NAME_NOT_RESOLVED) - Flagged as Suspicious Unreachable Domain")
                features['sandbox_threat_score'] = 60
                features['sandbox_error'] = "ERR_NAME_NOT_RESOLVED"
            elif 'ERR_CONNECTION_REFUSED' in err_msg or 'refused' in err_msg.lower():
                features['sandbox_threat_score'] = 45
                features['sandbox_error'] = "ERR_CONNECTION_REFUSED"
            else:
                features['sandbox_threat_score'] = 35
                features['sandbox_error'] = "BROWSER_ERROR"
            return features
        finally:
            if driver:
                driver.quit()
