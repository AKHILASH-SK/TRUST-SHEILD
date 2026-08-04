import requests
import json
from database import SessionLocal
from sqlalchemy import text

def verify_and_add_brand(brand_name, domain_to_check):
    """
    Queries Clearbit Autocomplete API for the domain.
    If the returned company name is related to the brand, we trust it and add to DB.
    Since we want to verify if 'domain_to_check' is an official domain for 'brand_name',
    we query Clearbit using the domain itself to see its official registered name.
    """
    try:
        url = f"https://autocomplete.clearbit.com/v1/companies/suggest?query={domain_to_check}"
        response = requests.get(url, timeout=5)
        
        if response.status_code == 200:
            results = response.json()
            if results:
                company = results[0]
                official_name = company.get("name", "").lower()
                official_domain = company.get("domain", "").lower()
                
                # Check if the brand name is in the official company name or vice versa
                if brand_name.lower() in official_name or official_name in brand_name.lower() or brand_name.lower() in official_domain:
                    print(f"Auto-verified {domain_to_check} belongs to {brand_name} (Registered as {company.get('name')})")
                    _add_alias_to_db(brand_name, domain_to_check)
                    return True
                    
        # Fallback: Query by brand name and see if domain matches
        url2 = f"https://autocomplete.clearbit.com/v1/companies/suggest?query={brand_name}"
        response2 = requests.get(url2, timeout=5)
        if response2.status_code == 200:
            results2 = response2.json()
            for company in results2:
                official_domain = company.get("domain", "").lower()
                if official_domain and (domain_to_check == official_domain or domain_to_check.endswith("." + official_domain)):
                    print(f"Auto-verified {domain_to_check} belongs to {brand_name} (Matched domain {official_domain})")
                    _add_alias_to_db(brand_name, domain_to_check)
                    return True
                    
        return False
    except Exception as e:
        print(f"Error checking Clearbit API: {e}")
        return False

def discover_and_add_brand(domain):
    """
    Given a domain, queries Clearbit to see if it belongs to a recognized brand.
    If it does, it adds the brand to the database automatically.
    Returns the brand name if found, otherwise None.
    """
    try:
        url = f"https://autocomplete.clearbit.com/v1/companies/suggest?query={domain}"
        response = requests.get(url, timeout=5)
        
        if response.status_code == 200:
            results = response.json()
            
            # If no results and it's a subdomain, try the root domain
            if not results and domain.count('.') > 1:
                parts = domain.split('.')
                # Simplistic root domain extraction (last two parts)
                root_domain = parts[-2] + '.' + parts[-1]
                url = f"https://autocomplete.clearbit.com/v1/companies/suggest?query={root_domain}"
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    results = response.json()
            
            if results:
                company = results[0]
                official_domain = company.get("domain", "").lower()
                official_name = company.get("name", "")
                
                # If the domain matches the company's official domain
                if official_domain and (domain == official_domain or domain.endswith("." + official_domain)):
                    print(f"🌟 [DYNAMIC DISCOVERY] Discovered new legitimate brand: {official_name} ({official_domain})")
                    _add_alias_to_db(official_name, domain)
                    return official_name
        return None
    except Exception as e:
        print(f"Error in brand discovery: {e}")
        return None

def _add_alias_to_db(brand_name, new_alias):
    db = SessionLocal()
    try:
        # Check if brand exists
        result = db.execute(text("SELECT id, aliases FROM official_brands WHERE name ILIKE :brand"), {"brand": brand_name}).fetchone()
        
        if result:
            brand_id = result[0]
            existing_aliases = result[1]
            if isinstance(existing_aliases, str):
                existing_aliases = json.loads(existing_aliases)
                
            if new_alias not in existing_aliases:
                existing_aliases.append(new_alias)
                db.execute(text("UPDATE official_brands SET aliases = :aliases WHERE id = :id"), 
                           {"aliases": json.dumps(existing_aliases), "id": brand_id})
                db.commit()
                print(f"Added {new_alias} to {brand_name} aliases in DB")
        else:
            # Create new brand entry
            aliases = [new_alias]
            db.execute(text("INSERT INTO official_brands (name, primary_domain, aliases) VALUES (:name, :domain, :aliases)"),
                       {"name": brand_name.capitalize(), "domain": new_alias, "aliases": json.dumps(aliases)})
            db.commit()
            print(f"Created new brand {brand_name.capitalize()} with domain {new_alias}")
    except Exception as e:
        print(f"Database error adding alias: {e}")
        db.rollback()
    finally:
        db.close()
