"""
Tier 3: Sandbox Analysis Module
Analyzes URLs using VirusTotal API + feature extraction for phishing detection
"""

import requests
import json
import ssl
import socket
import logging
import time
import re
from datetime import datetime
from urllib.parse import urlparse
from bs4 import BeautifulSoup

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SandboxAnalyzer:
    """
    Tier 3 Analysis: Performs deep sandbox analysis on URLs
    Combines multiple feature extractions with ML scoring
    """
    
    def __init__(self, virustotal_api_key):
        """Initialize with VirusTotal API key"""
        self.vt_api_key = virustotal_api_key
        self.vt_base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": virustotal_api_key}
        self.timeout = 10
        
        # Known legitimate domains (trusted brands)
        self.trusted_domains = {
            'paypal.com', 'paypal.co.uk', 'paypal.de', 'paypal.fr',
            'amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr',
            'apple.com', 'microsoft.com', 'google.com', 'facebook.com',
            'twitter.com', 'linkedin.com', 'instagram.com',
            'bank.com', 'chase.com', 'bofa.com', 'wellsfargo.com',
            'gmail.com', 'yahoo.com', 'outlook.com',
        }
    
    def analyze_url(self, url):
        """
        Complete Tier 3 sandbox analysis
        Returns: {
            "verdict": "DANGEROUS" | "SUSPICIOUS" | "SAFE",
            "confidence": 0-100,
            "score": 0-100,
            "analysis_type": "sandbox",
            "features": {...}
        }
        """
        try:
            print(f"\n{'='*80}")
            print(f"🔬 [TIER 3 - SANDBOX ANALYSIS] Starting analysis for: {url}")
            print(f"{'='*80}")
            
            features = {}
            
            # Step 1: Redirect chain tracking
            print(f"📍 [Step 1] Tracking redirects...")
            redirect_info = self._track_redirects(url)
            features['redirect_analysis'] = redirect_info['score']
            features['redirect_chain'] = redirect_info['chain']
            print(f"   - Chain length: {len(redirect_info['chain'])}")
            print(f"   - Final URL: {redirect_info['final_url']}")
            
            final_url = redirect_info['final_url']
            parsed_final = urlparse(final_url)
            final_domain = parsed_final.netloc.lower()
            
            # Step 2: Domain analysis
            print(f"🌐 [Step 2] Analyzing domain: {final_domain}")
            domain_info = self._analyze_domain(final_domain, url)
            features['domain_analysis'] = domain_info['score']
            features['domain_reputation'] = domain_info.get('reputation', 'unknown')
            
            # Step 3: SSL Certificate analysis
            print(f"🔐 [Step 3] Checking SSL certificate...")
            cert_info = self._extract_ssl_certificate(final_domain)
            features['certificate_analysis'] = cert_info['score']
            features['certificate_valid'] = cert_info['valid']
            features['certificate_org'] = cert_info.get('organization', 'Unknown')
            print(f"   - Valid: {cert_info['valid']}")
            print(f"   - Organization: {cert_info.get('organization', 'N/A')}")
            
            # Step 4: Form analysis (fetch & parse HTML)
            print(f"📋 [Step 4] Analyzing HTML forms...")
            form_info = self._analyze_forms(final_url)
            features['form_analysis'] = form_info['score']
            features['form_fields'] = form_info.get('fields', [])
            features['form_action'] = form_info.get('action_domain', 'N/A')
            print(f"   - Forms found: {form_info.get('forms_count', 0)}")
            print(f"   - Sensitive fields: {form_info.get('sensitive_fields_count', 0)}")
            
            # Step 5: JavaScript payload analysis
            print(f"⚙️  [Step 5] Analyzing JavaScript...")
            js_info = self._analyze_javascript(final_url)
            features['javascript_analysis'] = js_info['score']
            features['suspicious_js'] = js_info.get('suspicious_patterns', [])
            print(f"   - Suspicious patterns found: {len(js_info.get('suspicious_patterns', []))}")
            
            # Step 6: VirusTotal scan (AV detection - SCAN THE FINAL URL, NOT THE SHORT URL)
            print(f"🛡️  [Step 6] Running VirusTotal scan on final destination...")
            vt_info = self._virustotal_scan(final_url)  # Use final_url, not original url
            features['antivirus_analysis'] = vt_info['score']
            features['av_detection_ratio'] = vt_info.get('detection_ratio', '0/70')
            features['malicious_engines'] = vt_info.get('malicious_count', 0)
            print(f"   - Detection ratio: {vt_info.get('detection_ratio', '0/70')}")
            
            # Step 7: Brand mimicry check
            print(f"🎭 [Step 7] Checking brand mimicry...")
            mimicry_info = self._check_brand_mimicry(final_domain)
            features['brand_mimicry'] = mimicry_info['score']
            features['mimics_brand'] = mimicry_info.get('brand_matched', None)
            print(f"   - Mimics: {mimicry_info.get('brand_matched', 'None')}")
            
            # === CALCULATE FINAL SCORE ===
            print(f"\n🧮 [SCORING] Calculating final verdict...")
            total_score = (
                features['redirect_analysis'] +
                features['domain_analysis'] +
                features['certificate_analysis'] +
                features['form_analysis'] +
                features['javascript_analysis'] +
                features['antivirus_analysis'] +
                features['brand_mimicry']
            )
            
            # Apply multipliers for dangerous combinations
            multiplier_bonus = self._calculate_multiplier_bonus(features)
            total_score += multiplier_bonus
            
            total_score = min(100, total_score)  # Cap at 100
            
            # Determine verdict
            if total_score >= 70:
                verdict = "DANGEROUS"
                confidence = min(100, total_score)
            elif total_score >= 40:
                verdict = "SUSPICIOUS"
                confidence = total_score - 10  # Reduce confidence for borderline
            else:
                verdict = "SAFE"
                confidence = max(80, 100 - total_score)
            
            result = {
                "verdict": verdict,
                "confidence": int(confidence),
                "score": int(total_score),
                "analysis_type": "sandbox",
                "features": features,
                "timestamp": datetime.now().isoformat()
            }
            
            print(f"\n✅ [VERDICT] {verdict} (Score: {total_score}/100, Confidence: {confidence}%)")
            print(f"{'='*80}\n")
            
            return result
            
        except Exception as e:
            logger.error(f"Sandbox analysis error: {str(e)}")
            print(f"❌ [ERROR] Sandbox analysis failed: {str(e)}")
            return {
                "verdict": "SAFE",
                "confidence": 30,
                "score": 0,
                "analysis_type": "sandbox",
                "error": str(e)
            }
    
    # ============== FEATURE EXTRACTION METHODS ==============
    
    def _track_redirects(self, url):
        """Track redirect chain (Step 1) - Follow redirects to find final destination"""
        try:
            chain = []
            current_url = url
            max_redirects = 10
            suspicious_redirects = 0
            visited_urls = set()
            
            for i in range(max_redirects):
                try:
                    if current_url in visited_urls:
                        print(f"   ⚠️  Redirect loop detected at: {current_url}")
                        break
                    
                    visited_urls.add(current_url)
                    
                    # Use HEAD first for efficiency, fall back to GET if needed
                    try:
                        response = requests.head(
                            current_url,
                            allow_redirects=False,
                            timeout=5,
                            headers={'User-Agent': 'Mozilla/5.0'}
                        )
                    except:
                        # If HEAD fails, use GET
                        response = requests.get(
                            current_url,
                            allow_redirects=False,
                            timeout=5,
                            headers={'User-Agent': 'Mozilla/5.0'}
                        )
                    
                    chain.append({'url': current_url, 'status': response.status_code})
                    print(f"   → [{response.status_code}] {current_url}")
                    
                    # Check for redirect
                    if response.status_code in [301, 302, 303, 307, 308]:
                        next_url = response.headers.get('Location')
                        if next_url:
                            # Handle relative redirects
                            if not next_url.startswith('http'):
                                base = urlparse(current_url).scheme + '://' + urlparse(current_url).netloc
                                next_url = base + next_url
                            
                            # Check if redirecting to different domain
                            prev_domain = urlparse(current_url).netloc
                            next_domain = urlparse(next_url).netloc
                            
                            if prev_domain != next_domain:
                                suspicious_redirects += 1
                                print(f"   ⚠️  Cross-domain redirect: {prev_domain} → {next_domain}")
                            
                            current_url = next_url
                        else:
                            # Redirect without location header
                            print(f"   ⚠️  Redirect without Location header")
                            break
                    else:
                        # No redirect, this is the final URL
                        break
                        
                except Exception as e:
                    print(f"   ❌ Error following redirect: {str(e)}")
                    logger.warning(f"Error following redirect: {str(e)}")
                    break
            
            # Score: Each cross-domain redirect = +2 points (max 10)
            score = min(10, suspicious_redirects * 2)
            
            print(f"   Chain length: {len(chain)}")
            print(f"   Final URL: {current_url}")
            
            return {
                'score': score,
                'chain': chain,
                'final_url': current_url,
                'redirect_count': len(chain) - 1,
                'suspicious_count': suspicious_redirects
            }
            
        except Exception as e:
            logger.warning(f"Redirect tracking error: {str(e)}")
            return {
                'score': 0,
                'chain': [{'url': url}],
                'final_url': url,
                'redirect_count': 0,
                'suspicious_count': 0
            }
    
    def _analyze_domain(self, domain, original_url):
        """Check if domain is legitimate or suspicious"""
        score = 0
        reputation = "unknown"
        
        try:
            # Check if domain is in trusted list
            if any(domain.endswith(trusted) for trusted in self.trusted_domains):
                return {'score': 0, 'reputation': 'trusted'}
            
            # Check for typosquatting
            if self._is_typosquatted(domain):
                score += 8
                reputation = "typosquatted"
            
            # Check for homoglyphs (l vs 1, 0 vs O, etc)
            if self._has_homoglyphs(domain):
                score += 6
                reputation = "suspicious_chars"
            
            # Check domain age (new domains are suspicious if they mimic brands)
            try:
                import whois
                whois_data = whois.whois(domain)
                creation_date = whois_data.creation_date
                
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                
                if creation_date:
                    age_days = (datetime.now() - creation_date).days
                    if age_days < 7:  # Very new domain
                        score += 4
                        if self._looks_like_brand_name(domain):
                            score += 4  # Double suspicious if new AND looks like brand
            except:
                pass  # WHOIS might fail, continue
            
            # Check for excessive subdomains
            if domain.count('.') > 3:
                score += 3
            
        except Exception as e:
            logger.warning(f"Domain analysis error: {str(e)}")
        
        return {
            'score': min(10, score),
            'reputation': reputation,
            'domain': domain
        }
    
    def _extract_ssl_certificate(self, domain):
        """Extract SSL certificate information"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
            
            score = 0
            
            # Check certificate validity
            if cert:
                # Extract organization
                org = None
                for sub in cert.get('subject', []):
                    for key, val in sub:
                        if key == 'organizationName':
                            org = val
                            break
                
                # Check if cert domain matches
                cn = None
                for sub in cert.get('subject', []):
                    for key, val in sub:
                        if key == 'commonName':
                            cn = val
                            break
                
                # If organization is suspicious or doesn't match domain
                if org and self._is_suspicious_org(org):
                    score += 7
                elif not cn or not self._domain_matches_cert(domain, cn):
                    score += 6
                
                return {
                    'valid': True,
                    'score': min(10, score),
                    'organization': org or "Unknown",
                    'common_name': cn or domain
                }
            else:
                return {
                    'valid': False,
                    'score': 10,
                    'organization': "No Certificate",
                    'common_name': domain
                }
                
        except ssl.SSLError:
            return {
                'valid': False,
                'score': 10,
                'organization': "Invalid Certificate",
                'common_name': domain
            }
        except Exception as e:
            logger.warning(f"SSL check error: {str(e)}")
            return {
                'valid': False,
                'score': 5,
                'organization': "Unknown",
                'common_name': domain
            }
    
    def _analyze_forms(self, url):
        """Analyze HTML forms for suspicious patterns"""
        score = 0
        forms_count = 0
        sensitive_fields_count = 0
        action_domain = "N/A"
        fields = []
        
        try:
            response = requests.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')  # Use html.parser instead of lxml
            forms = soup.find_all('form')
            forms_count = len(forms)
            
            # Dangerous field patterns
            dangerous_patterns = [
                r'ssn|social\s?security|social-security',
                r'credit.?card|cc\s?number|card.?number',
                r'cvv|cvc|security.?code',
                r'routing.?number|account.?number',
                r'mother.?maiden|maiden.?name',
                r'date.?birth|dob|birth.?date'
            ]
            
            if forms:
                for form in forms:
                    # Get form action
                    action = form.get('action', '')
                    if action:
                        action_domain = urlparse(action).netloc
                    
                    # Find all input fields
                    inputs = form.find_all(['input', 'textarea', 'select'])
                    
                    for inp in inputs:
                        field_name = inp.get('name', '').lower()
                        field_type = inp.get('type', '').lower()
                        field_placeholder = inp.get('placeholder', '').lower()
                        
                        fields.append({
                            'name': field_name,
                            'type': field_type,
                            'placeholder': field_placeholder
                        })
                        
                        # Check for dangerous field patterns
                        search_text = f"{field_name} {field_placeholder}"
                        for pattern in dangerous_patterns:
                            if re.search(pattern, search_text, re.IGNORECASE):
                                sensitive_fields_count += 1
                                score += 5
                                break
            
            # If form exists but action doesn't go to same domain
            if forms_count > 0 and action_domain != "N/A":
                parsed_url = urlparse(url)
                if action_domain != parsed_url.netloc:
                    score += 6  # Form sends data to different domain
            
        except Exception as e:
            logger.warning(f"Form analysis error: {str(e)}")
        
        return {
            'score': min(15, score),
            'forms_count': forms_count,
            'sensitive_fields_count': sensitive_fields_count,
            'action_domain': action_domain,
            'fields': fields
        }
    
    def _analyze_javascript(self, url):
        """Analyze page JavaScript for malicious patterns"""
        score = 0
        suspicious_patterns = []
        
        try:
            response = requests.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
            response.raise_for_status()
            
            # Extract all script content
            soup = BeautifulSoup(response.content, 'html.parser')
            scripts = soup.find_all('script')
            
            all_script_content = ' '.join([script.string or '' for script in scripts if script.string])
            
            # Dangerous JS patterns
            dangerous_js_patterns = [
                (r'fetch\(["\'](?!https?://\1)', 'External data fetch'),
                (r'XMLHttpRequest\(["\'](?!https?://\1)', 'XHR to external domain'),
                (r'navigator\.sendBeacon', 'Beacon exfiltration'),
                (r'eval\s*\(', 'Eval execution'),
                (r'Function\s*\(', 'Dynamic function creation'),
                (r'document\.form|form\.submit', 'Form submission hijack'),
                (r'keylogger|keypress|keydown.*log', 'Keylogging'),
                (r'window\.location.*=.*[a-z0-9]{50,}', 'Redirect to encoded URL'),
                (r'atob|btoa|String\.fromCharCode', 'Obfuscation attempt'),
                (r'setInterval.*\d{1,3}\s*[,\)]', 'Suspicious interval')
            ]
            
            for pattern, description in dangerous_js_patterns:
                if re.search(pattern, all_script_content, re.IGNORECASE):
                    suspicious_patterns.append(description)
                    score += 1
            
        except Exception as e:
            logger.warning(f"JavaScript analysis error: {str(e)}")
        
        return {
            'score': min(10, score),
            'suspicious_patterns': suspicious_patterns
        }
    
    def _virustotal_scan(self, url):
        """Get VirusTotal detection ratio"""
        try:
            print(f"\n🔵 [VirusTotal] Starting scan for: {url}")
            print(f"   API Key: {self.vt_api_key[:20]}..." if self.vt_api_key else "❌ NO API KEY")
            
            if not self.vt_api_key:
                print(f"❌ [VirusTotal] NO API KEY FOUND - Cannot scan")
                return {'score': 0, 'detection_ratio': '0/70', 'malicious_count': 0, 'error': 'No API key'}
            
            # Step 1: Submit URL to VirusTotal
            print(f"   📤 Submitting URL to VirusTotal...")
            print(f"   Endpoint: {self.vt_base_url}/urls")
            print(f"   Headers: {self.headers}")
            
            data = {"url": url}
            submit_response = requests.post(
                f"{self.vt_base_url}/urls",
                data=data,
                headers=self.headers,
                timeout=self.timeout
            )
            
            print(f"   📊 Submit Response Status: {submit_response.status_code}")
            print(f"   📊 Submit Response Body: {submit_response.text[:500]}")
            
            analysis_id = None
            if submit_response.status_code in [200, 204]:
                print(f"   ✅ URL submitted successfully")
                try:
                    result = submit_response.json()
                    print(f"   📄 Submit JSON: {result}")
                    if 'data' in result and 'id' in result['data']:
                        analysis_id = result['data']['id']
                        print(f"   🆔 Analysis ID: {analysis_id}")
                    else:
                        print(f"   ⚠️  No analysis ID in response: {result}")
                except Exception as json_err:
                    print(f"   ⚠️  Could not parse submit response as JSON: {json_err}")
            else:
                print(f"   ❌ Submission failed: {submit_response.status_code}")
                print(f"   Response text: {submit_response.text[:500]}")
                return {'score': 0, 'detection_ratio': '0/70', 'malicious_count': 0, 'error': f'Submission failed: {submit_response.status_code}'}
            
            # Step 2: Wait for analysis to complete
            print(f"   ⏳ Waiting for analysis (3 seconds)...")
            time.sleep(3)
            
            # Step 3: Get results using the analysis ID
            if not analysis_id:
                print(f"   ❌ No analysis ID available, cannot retrieve results")
                return {'score': 0, 'detection_ratio': '0/70', 'malicious_count': 0, 'error': 'No analysis ID'}
            
            print(f"   🔍 Retrieving analysis results...")
            print(f"   Endpoint: {self.vt_base_url}/analyses/{analysis_id}")
            
            analysis_response = requests.get(
                f"{self.vt_base_url}/analyses/{analysis_id}",
                headers=self.headers,
                timeout=self.timeout
            )
            
            print(f"   📊 Analysis Response Status: {analysis_response.status_code}")
            print(f"   📊 Analysis Response Body: {analysis_response.text[:1000]}")
            
            if analysis_response.status_code == 200:
                data = analysis_response.json()
                print(f"   📄 Analysis JSON received (length: {len(analysis_response.text)})")
                
                if 'data' not in data:
                    print(f"   ⏳ No data in response yet")
                    return {'score': 0, 'detection_ratio': '0/70', 'malicious_count': 0, 'note': 'Analysis pending'}
                
                attrs = data['data'].get('attributes', {})
                stats = attrs.get('last_analysis_stats', {})
                
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                undetected = stats.get('undetected', 0)
                harmless = stats.get('harmless', 0)
                total = malicious + suspicious + undetected + harmless
                
                detection_ratio = f"{malicious + suspicious}/{total if total > 0 else 70}"
                
                print(f"   ✅ Analysis Complete!")
                print(f"   - Malicious: {malicious}")
                print(f"   - Suspicious: {suspicious}")
                print(f"   - Harmless: {harmless}")
                print(f"   - Undetected: {undetected}")
                print(f"   - Detection Ratio: {detection_ratio}")
                
                # Score: Each malicious detection = +1.5 point, suspicious = +0.5
                score = min(20, (malicious * 1.5) + (suspicious * 0.5))
                
                return {
                    'score': int(score),
                    'detection_ratio': detection_ratio,
                    'malicious_count': malicious,
                    'suspicious_count': suspicious,
                    'harmless_count': harmless
                }
            else:
                print(f"   ❌ Failed to get results: {analysis_response.status_code}")
                print(f"   Response text: {analysis_response.text[:500]}")
                return {'score': 0, 'detection_ratio': '0/70', 'malicious_count': 0, 'error': f'Get failed: {analysis_response.status_code}'}
            
        except Exception as e:
            print(f"   ❌ Exception in VirusTotal scan: {str(e)}")
            import traceback
            print(f"   Traceback:")
            traceback.print_exc()
            logger.warning(f"VirusTotal scan error: {str(e)}")
            return {'score': 0, 'detection_ratio': '0/70', 'malicious_count': 0, 'error': str(e)}
    
    def _check_brand_mimicry(self, domain):
        """Check if domain mimics known brands"""
        score = 0
        brand_matched = None
        
        # Known brand patterns (simplified)
        brand_patterns = {
            'paypal': ['paypa1', 'paypa', 'p4ypal', 'paypa.'],
            'amazon': ['amaz0n', 'amazo', 'amzon', 'amz0n'],
            'apple': ['appl3', 'apple.', 'appple', 'aple'],
            'microsoft': ['microso', 'microsoft.', 'mıcrosoft'],
            'google': ['g00gle', 'google.', 'gooqle']
        }
        
        domain_lower = domain.lower()
        
        for brand, variations in brand_patterns.items():
            if brand in domain_lower:
                score += 8
                brand_matched = brand
            else:
                for variation in variations:
                    if variation in domain_lower:
                        score += 6
                        brand_matched = f"{brand} (typo)"
                        break
        
        return {
            'score': min(12, score),
            'brand_matched': brand_matched
        }
    
    # ============== HELPER METHODS ==============
    
    def _is_typosquatted(self, domain):
        """Check for obvious typosquatting"""
        known_brands = ['paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook']
        domain_lower = domain.lower()
        
        for brand in known_brands:
            # Check for one-character difference
            if self._levenshtein_distance(brand, domain_lower.split('.')[0]) <= 2:
                if domain_lower != brand:
                    return True
        return False
    
    def _has_homoglyphs(self, domain):
        """Check for homoglyph characters (0 vs O, 1 vs l, etc)"""
        if '0' in domain or '1' in domain:
            return True
        return False
    
    def _looks_like_brand_name(self, domain):
        """Check if domain looks like it's trying to impersonate a brand"""
        known_brands = ['paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook', 'bank', 'finance']
        domain_lower = domain.split('.')[0].lower()
        
        for brand in known_brands:
            if brand in domain_lower:
                return True
        return False
    
    def _is_suspicious_org(self, org):
        """Check if certificate org is suspicious"""
        suspicious_terms = ['hosting', 'server', 'cloud', 'anonymous', 'privacy', 'vpn', 'proxy']
        org_lower = org.lower()
        
        return any(term in org_lower for term in suspicious_terms)
    
    def _domain_matches_cert(self, domain, cert_cn):
        """Check if domain matches certificate CN"""
        if not cert_cn:
            return False
        
        cert_cn = cert_cn.lower()
        domain = domain.lower()
        
        # Handle wildcards
        if cert_cn.startswith('*.'):
            cert_cn = cert_cn[2:]
            return domain.endswith(cert_cn)
        
        return domain == cert_cn
    
    def _levenshtein_distance(self, s1, s2):
        """Calculate Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def _calculate_multiplier_bonus(self, features):
        """Apply multiplier bonuses for dangerous feature combinations"""
        bonus = 0
        
        # Exact brand clone + cert issues
        if features.get('brand_mimicry', 0) > 8 and features.get('certificate_analysis', 0) > 5:
            bonus += 10
            print(f"   🚨 MULTIPLIER: Brand clone + cert issues (+10)")
        
        # Form with sensitive fields + suspicious domain
        if features.get('form_analysis', 0) > 10 and features.get('domain_analysis', 0) > 5:
            bonus += 8
            print(f"   🚨 MULTIPLIER: Risky form + suspicious domain (+8)")
        
        # Multiple redirects + risky website
        if features.get('redirect_analysis', 0) > 5 and (features.get('form_analysis', 0) > 5 or features.get('domain_analysis', 0) > 5):
            bonus += 5
            print(f"   🚨 MULTIPLIER: Series of redirects + suspicious site (+5)")
        
        # AV engines flagging it + other red flags
        if features.get('antivirus_analysis', 0) > 8 and features.get('javascript_analysis', 0) > 2:
            bonus += 7
            print(f"   🚨 MULTIPLIER: AV detections + suspicious JS (+7)")
        
        return bonus


class URLFeatureAnalyzer:
    """
    Extract features from URL for additional analysis
    """
    
    @staticmethod
    def extract_features(url):
        """Extract security-relevant features from URL"""
        features = {
            "url_length": len(url),
            "has_https": url.startswith("https://"),
            "subdomain_count": url.count("."),
            "has_ip_address": URLFeatureAnalyzer._has_ip(url),
            "suspicious_chars": URLFeatureAnalyzer._count_suspicious_chars(url),
            "url_entropy": URLFeatureAnalyzer._calculate_entropy(url)
        }
        return features
    
    @staticmethod
    def _has_ip(url):
        """Check if URL contains IP address"""
        import re
        pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        return bool(re.search(pattern, url))
    
    @staticmethod
    def _count_suspicious_chars(url):
        """Count suspicious characters in URL"""
        suspicious = "!@#$%^&*()"
        return sum(1 for char in url if char in suspicious)
    
    @staticmethod
    def _calculate_entropy(url):
        """Calculate Shannon entropy of URL (higher = more random)"""
        import math
        if not url:
            return 0
        
        entropy = 0
        for char in set(url):
            probability = url.count(char) / len(url)
            entropy -= probability * math.log2(probability)
        
        return round(entropy, 2)
