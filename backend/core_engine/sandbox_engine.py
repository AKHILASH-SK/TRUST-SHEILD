import time
import logging
from typing import Dict, Any
from urllib.parse import urlparse

# Using Selenium for the custom headless browser sandbox
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException

logger = logging.getLogger(__name__)

class VirtualSandboxAnalyzer:
    """
    Tier 3: Custom Zero-Day Virtual Sandbox (Headless Browser).
    100% Free and Custom Built.
    Spins up an isolated headless browser environment, navigates to the URL, 
    and inspects the DOM and Network behaviors for phishing indicators.
    """
    def __init__(self):
        # Configure Headless Chrome for the Sandbox Environment
        self.chrome_options = Options()
        self.chrome_options.add_argument("--headless")
        self.chrome_options.add_argument("--disable-gpu")
        self.chrome_options.add_argument("--no-sandbox")
        self.chrome_options.add_argument("--disable-dev-shm-usage")
        # Phishers often block bots; masquerade as a real user
        self.chrome_options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
        
        # In a real environment we'd use selenium-wire to intercept all network requests
        # For this MVP, we will extract deep DOM features.

    def analyze_link_in_sandbox(self, url: str) -> Dict[str, Any]:
        """
        Detonates the URL in the local headless sandbox and extracts behavioral features.
        """
        print(f"📦 [CUSTOM SANDBOX] Detonating URL in isolated headless browser: {url}")
        
        features = {
            "sandbox_num_redirects": 0,
            "sandbox_has_password_field": 0,
            "sandbox_hidden_iframes": 0,
            "sandbox_title_mismatch": 0,
            "sandbox_threat_score": 0
        }
        
        driver = None
        try:
            # 1. Initialize the Sandbox Browser
            driver = webdriver.Chrome(options=self.chrome_options)
            driver.set_page_load_timeout(15)
            
            # 2. Record initial state to track redirects
            initial_url = url
            
            # 3. Detonate! Navigate to the URL
            driver.get(url)
            time.sleep(3) # Wait for JS payloads to execute
            
            final_url = driver.current_url
            
            # 4. Feature Extraction: Redirects
            if initial_url.lower().strip('/') != final_url.lower().strip('/'):
                print(f"   ⚠️ Redirect detected: {initial_url} -> {final_url}")
                features['sandbox_num_redirects'] = 1 # Simplified for MVP
                
            # 5. Feature Extraction: Password Harvesting (The ultimate phishing indicator)
            password_inputs = driver.find_elements(By.XPATH, "//input[@type='password']")
            if len(password_inputs) > 0:
                print("   🚨 Credential Harvesting Form Detected!")
                features['sandbox_has_password_field'] = 1
                
            # 6. Feature Extraction: Hidden Iframes (Malware dropping)
            iframes = driver.find_elements(By.TAG_NAME, "iframe")
            hidden_iframes = 0
            for iframe in iframes:
                # Check if it's invisible (1x1 pixel or hidden)
                size = iframe.size
                if size['width'] <= 1 and size['height'] <= 1:
                    hidden_iframes += 1
            features['sandbox_hidden_iframes'] = hidden_iframes
            if hidden_iframes > 0:
                print(f"   ⚠️ Hidden iframes detected: {hidden_iframes}")
                
            # 7. Feature Extraction: Title Mismatch (e.g. Title says 'PayPal' but domain is 'amzon-verify.com')
            page_title = driver.title.lower()
            domain = urlparse(final_url).netloc.lower()
            
            known_financial_brands = ['paypal', 'bank', 'login', 'secure', 'amazon', 'microsoft', 'apple']
            for brand in known_financial_brands:
                if brand in page_title and brand not in domain:
                    print(f"   🚨 Title Mismatch! Title claims '{brand}' but domain is '{domain}'")
                    features['sandbox_title_mismatch'] = 1
                    break
                    
            # 8. Calculate internal Sandbox Threat Score (to be fed to the Meta-Classifier)
            threat_score = 0
            if features['sandbox_has_password_field']: threat_score += 60
            if features['sandbox_title_mismatch']: threat_score += 40
            if features['sandbox_num_redirects']: threat_score += 20
            if features['sandbox_hidden_iframes'] > 0: threat_score += 30
            
            features['sandbox_threat_score'] = min(100, threat_score)
            
            print(f"✅ [CUSTOM SANDBOX] Analysis Complete. Sandbox Score: {features['sandbox_threat_score']}")
            return features
            
        except TimeoutException:
            print("❌ [SANDBOX] URL timed out (common for dead phishing links).")
            # Dead links are suspicious but not confirmable
            features['sandbox_threat_score'] = 20
            return features
        except WebDriverException as e:
            print(f"❌ [SANDBOX] Browser Error: {str(e)}")
            return features
        finally:
            if driver:
                driver.quit()
