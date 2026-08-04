import re
import json
import psycopg
import os
from dotenv import load_dotenv

load_dotenv()

DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': int(os.getenv('DB_PORT', '5432')),
    'dbname': os.getenv('DB_NAME', 'trustshield_db'),
    'user': os.getenv('DB_USER', 'postgres'),
    'password': os.getenv('DB_PASSWORD', 'postgres')
}

def parse_kotlin_registry(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    brands = []
    # Regex to extract OfficialBrand definitions
    pattern = re.compile(
        r'OfficialBrand\s*\(\s*name\s*=\s*"([^"]+)",\s*primaryDomain\s*=\s*"([^"]+)",\s*aliases\s*=\s*(.*?),\s*trustedSubdomains\s*=\s*(.*?),\s*trustedCdns\s*=\s*(.*?)\n\s*\)',
        re.DOTALL
    )

    def extract_list(value_str):
        if 'emptyList()' in value_str:
            return []
        list_match = re.search(r'listOf\((.*?)\)', value_str, re.DOTALL)
        if list_match:
            items_str = list_match.group(1)
            return [item.strip().strip('"').strip() for item in items_str.split(',') if item.strip()]
        return []

    for match in pattern.finditer(content):
        name = match.group(1)
        primary_domain = match.group(2)
        aliases = extract_list(match.group(3))
        subdomains = extract_list(match.group(4))
        cdns = extract_list(match.group(5))

        brands.append({
            'name': name,
            'primary_domain': primary_domain,
            'aliases': aliases,
            'trusted_subdomains': subdomains,
            'trusted_cdns': cdns
        })
    return brands

def seed_database():
    kotlin_file = r'../app/src/main/java/com/example/trustshield/OfficialDomainRegistry.kt'
    
    brands = parse_kotlin_registry(kotlin_file)
    if not brands:
        print("No brands found to seed.")
        return

    print(f"Found {len(brands)} brands. Seeding database...")
    
    conn = psycopg.connect(**DB_CONFIG)
    cur = conn.cursor()
    
    # Run init_db first just in case
    import init_db
    init_db.init_database()

    count = 0
    for brand in brands:
        try:
            cur.execute("""
                INSERT INTO official_brands 
                (name, primary_domain, aliases, trusted_subdomains, trusted_cdns)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (name) DO UPDATE SET
                    primary_domain = EXCLUDED.primary_domain,
                    aliases = EXCLUDED.aliases,
                    trusted_subdomains = EXCLUDED.trusted_subdomains,
                    trusted_cdns = EXCLUDED.trusted_cdns;
            """, (
                brand['name'], 
                brand['primary_domain'], 
                json.dumps(brand['aliases']), 
                json.dumps(brand['trusted_subdomains']), 
                json.dumps(brand['trusted_cdns'])
            ))
            count += 1
        except Exception as e:
            print(f"Failed to insert {brand['name']}: {e}")
            conn.rollback()
            continue

    conn.commit()
    cur.close()
    conn.close()
    print(f"Successfully seeded {count} brands into official_brands table!")

if __name__ == "__main__":
    seed_database()
