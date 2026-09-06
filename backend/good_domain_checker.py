import requests
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class GoodDomainChecker:
    """
    Tier 2.5: API-Driven 'Known Good' Domain Checker.
    Uses VirusTotal's Global Popularity Rankings to determine if a 
    domain (or its root domain) is a highly recognized, legitimate website.
    """
    
    def __init__(self, virustotal_api_key):
        self.vt_api_key = virustotal_api_key
        self.vt_base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": self.vt_api_key}
        self.timeout = 5

    def get_vt_reputation(self, url: str) -> dict:
        """
        Queries VirusTotal API and returns structured reputation data:
        - is_whitelisted (bool)
        - malicious_count (int)
        - popularity_rank (int)
        - vt_risk_score (float 0.0 - 100.0)
        - provider (str)
        """
        result = {
            "is_whitelisted": False,
            "malicious_count": 0,
            "popularity_rank": 99999999,
            "vt_risk_score": 35.0,
            "provider": ""
        }
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            if domain.startswith('www.'):
                domain = domain[4:]
                
            endpoint = f"{self.vt_base_url}/domains/{domain}"
            response = requests.get(endpoint, headers=self.headers, timeout=self.timeout)
            if response.status_code != 200:
                result["vt_risk_score"] = 40.0
                return result
                
            data = response.json().get('data', {}).get('attributes', {})
            stats = data.get('last_analysis_stats', {})
            malicious_count = stats.get('malicious', 0)
            result["malicious_count"] = malicious_count
            
            if malicious_count >= 2:
                result["is_whitelisted"] = False
                result["vt_risk_score"] = 95.0
                logger.warning(f"[Tier 2.5] Domain '{domain}' is flagged malicious by {malicious_count} VT engines!")
                return result
                
            popularity_ranks = data.get('popularity_ranks', {})
            best_rank = 99999999
            winning_provider = ""
            for provider, rank_data in popularity_ranks.items():
                rank = rank_data.get('rank', 99999999)
                if rank < best_rank:
                    best_rank = rank
                    winning_provider = provider
                    
            result["popularity_rank"] = best_rank
            result["provider"] = winning_provider
            
            if best_rank < 100000 and malicious_count == 0:
                result["is_whitelisted"] = True
                result["vt_risk_score"] = 0.0
                logger.info(f"🛡️ [WHITELIST API] '{domain}' safely verified! Global Rank: #{best_rank} (via {winning_provider}).")
            elif best_rank < 500000 and malicious_count == 0:
                result["is_whitelisted"] = True
                result["vt_risk_score"] = 10.0
                logger.info(f"🛡️ [WHITELIST API] '{domain}' top 500k verified! Global Rank: #{best_rank} (via {winning_provider}).")
            else:
                result["is_whitelisted"] = False
                result["vt_risk_score"] = 35.0
                logger.info(f"[Tier 2.5] '{domain}' is unranked or low rank ({best_rank}). Proceeding to Sandbox.")
                
            return result
        except Exception as e:
            logger.error(f"[Tier 2.5 API Error] {str(e)}.")
            return result

    def is_known_good_domain(self, url: str) -> bool:
        """
        Checks Global Popularity Rank via VirusTotal API.
        Handles subdomains and endpoints automatically.
        """
        rep = self.get_vt_reputation(url)
        return rep.get("is_whitelisted", False)
