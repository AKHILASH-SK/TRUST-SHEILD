import requests
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class GoodDomainChecker:
    "\""
    Tier 2.5: API-Driven 'Known Good' Domain Checker.
    Uses VirusTotal's Global Popularity Rankings to determine if a 
    domain (or its root domain) is a highly recognized, legitimate website.
    "\""
    
    def __init__(self, virustotal_api_key):
        self.vt_api_key = virustotal_api_key
        self.vt_base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": self.vt_api_key}
        self.timeout = 5

    def is_known_good_domain(self, url):
        "\""
        Checks Global Popularity Rank via VirusTotal API.
        Handles subdomains and endpoints automatically.
        "\""
        try:
            # Safely extract just the domain from complex URLs (e.g., offers.myntra.com/sale -> offers.myntra.com)
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            
            if domain.startswith('www.'):
                domain = domain[4:]
                
            # Call VirusTotal API to get Domain Intelligence
            endpoint = f"{self.vt_base_url}/domains/{domain}"
            response = requests.get(endpoint, headers=self.headers, timeout=self.timeout)
            
            # If VT doesn't have it, it's definitely not a top global domain
            if response.status_code != 200:
                logger.info(f"[Tier 2.5] Domain '{domain}' not found in global databases. Proceeding to Sandbox.")
                return False
                
            data = response.json().get('data', {}).get('attributes', {})
            
            # 1. Ensure the domain isn't known to be malicious by a vast majority
            stats = data.get('last_analysis_stats', {})
            malicious_count = stats.get('malicious', 0)
            if malicious_count >= 3:
                logger.warning(f"[Tier 2.5] Domain '{domain}' is popular but flagged malicious! Forcing Sandbox.")
                return False

            # 2. Check Global Popularity Ranks (Alexa, Cisco Umbrella, Statvoo)
            popularity_ranks = data.get('popularity_ranks', {})
            
            is_highly_popular = False
            best_rank = 99999999
            winning_provider = ""
            
            for provider, rank_data in popularity_ranks.items():
                rank = rank_data.get('rank', 99999999)
                # If the website is in the Top 500,000 globally, it is an established legitimate site
                if rank < 500000:
                    is_highly_popular = True
                    if rank < best_rank:
                        best_rank = rank
                        winning_provider = provider
            
            if is_highly_popular:
                logger.info(f"? [WHITELIST API] '{domain}' safely verified! Global Rank: #{best_rank} (via {winning_provider}). Bypassing Sandbox.")
                return True
                
            logger.info(f"[Tier 2.5] '{domain}' is not globally ranked high enough. Proceeding to Sandbox.")
            return False

        except Exception as e:
            logger.error(f"[Tier 2.5 API Error] {str(e)}. Falling back to Sandbox.")
            return False
