import requests
import json
import os
from tqdm import tqdm

MITRE_CTI_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "mitre_data")
OUTPUT_FILE = os.path.join(DATA_DIR, "parsed_techniques.json")

def fetch_mitre_data():
    """Fetches the latest STIX 2.1 Enterprise ATT&CK JSON from MITRE's CTI repo."""
    print(f"Fetching MITRE ATT&CK data from {MITRE_CTI_URL}...")
    response = requests.get(MITRE_CTI_URL)
    response.raise_for_status()
    return response.json()

def parse_techniques(stix_data):
    """Extracts T-IDs, names, descriptions, and platforms from STIX objects."""
    print("Parsing techniques and sub-techniques...")
    techniques = []
    
    objects = stix_data.get("objects", [])
    
    for obj in tqdm(objects, desc="Processing STIX objects"):
        # We are interested in attack-pattern objects (which represent techniques)
        if obj.get("type") == "attack-pattern":
            # Extract T-ID from external_references
            t_id = None
            url = None
            if "external_references" in obj:
                for ref in obj["external_references"]:
                    if ref.get("source_name") == "mitre-attack":
                        t_id = ref.get("external_id")
                        url = ref.get("url")
                        break
            
            if t_id:
                # Some descriptions have citation markers like (Citation: Name). 
                # For now, we extract the raw description. Future steps can clean this.
                techniques.append({
                    "t_id": t_id,
                    "name": obj.get("name", ""),
                    "description": obj.get("description", ""),
                    "platforms": obj.get("x_mitre_platforms", []),
                    "tactics": [kc.get("phase_name") for kc in obj.get("kill_chain_phases", []) if kc.get("kill_chain_name") == "mitre-attack"],
                    "url": url,
                    "is_subtechnique": obj.get("x_mitre_is_subtechnique", False)
                })
                
    return techniques

def main():
    os.makedirs(DATA_DIR, exist_ok=True)
    
    try:
        stix_data = fetch_mitre_data()
        techniques = parse_techniques(stix_data)
        
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump(techniques, f, indent=4, ensure_ascii=False)
            
        print(f"\n✅ Successfully extracted {len(techniques)} techniques/sub-techniques.")
        print(f"📁 Saved to {OUTPUT_FILE}")
        
    except Exception as e:
        print(f"❌ Error during ingestion: {e}")

if __name__ == "__main__":
    main()
