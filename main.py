import os
os.environ["ANONYMIZED_TELEMETRY"] = "False"
os.environ["TOKENIZERS_PARALLELISM"] = "false"

import json
import argparse
import time
import re
from tqdm import tqdm
from dotenv import load_dotenv
from src.pipeline.parse_reports import parse_and_chunk_pdf
from src.rag.extractor import get_vector_store, extract_ttps
from google import genai

# Load environment variables from .env file
load_dotenv()

FINAL_REPORTS_DIR = os.path.join("data", "final_reports")

class APIKeyManager:
    def __init__(self):
        # Support either plural GEMINI_API_KEYS (comma separated) or singular GEMINI_API_KEY
        keys_str = os.environ.get("GEMINI_API_KEYS") or os.environ.get("GEMINI_API_KEY")
        
        # Fallback to Streamlit secrets if running in Streamlit Cloud
        if not keys_str:
            try:
                import streamlit as st
                keys_str = st.secrets.get("GEMINI_API_KEYS") or st.secrets.get("GEMINI_API_KEY")
            except (ImportError, FileNotFoundError, Exception):
                pass
                
        if not keys_str:
            raise ValueError("No API keys found. Please set GEMINI_API_KEYS in your .env file or Streamlit Cloud Secrets.")
        
        # Parse comma-separated keys and remove empty strings/whitespace
        self.keys = [k.strip() for k in keys_str.split(",") if k.strip()]
        self.current_index = 0
        
    def get_current_key(self):
        return self.keys[self.current_index]
        
    def rotate_key(self):
        self.current_index = (self.current_index + 1) % len(self.keys)
        print(f"\n🔄 Rate limit hit. Rotating API key (Switching to Key {self.current_index + 1}/{len(self.keys)})")
        return self.get_current_key()

def analyze_report(pdf_path: str, output_path: str = None):
    print(f"🚀 Starting TTP Extraction pipeline for: {pdf_path}")
    
    # 1. Parse and Chunk
    print("\n--- Phase 1: Parsing & Chunking ---")
    chunks_file = parse_and_chunk_pdf(pdf_path)
    with open(chunks_file, "r", encoding="utf-8") as f:
        chunk_data = json.load(f)
    chunks = chunk_data.get("chunks", [])
    
    # 2. Setup DB and LLM
    print("\n--- Phase 2: Knowledge Base & LLM Init ---")
    db = get_vector_store()
    
    try:
        key_manager = APIKeyManager()
        client = genai.Client(api_key=key_manager.get_current_key())
        print(f"Loaded {len(key_manager.keys)} API key(s) for rotation.")
    except Exception as e:
        print(f"❌ {e}")
        raise Exception(f"Configuration Error: {e}")
    
    # 3. Extract TTPs
    print("\n--- Phase 3: TTP Extraction ---")
    all_ttps = []
    current_model = "gemini-2.5-flash"
    
    # We loop through all the extracted chunks and ask the LLM if there are TTPs inside
    for i, chunk in enumerate(tqdm(chunks, desc="Analyzing chunks via LLM")):
        # Max retries is 2x the number of keys we have, ensuring we can cycle through fully
        max_retries = len(key_manager.keys) * 2 
        for attempt in range(max_retries):
            try:
                res = extract_ttps(chunk, db, client, model_name=current_model)
                if res.contains_behavior: # Only process chunks where model confirmed threat activity
                    for ttp in res.ttps:
                        # Append findings with tracing info back to the chunk
                        all_ttps.append({
                            "t_id": ttp.t_id,
                            "name": ttp.name,
                            "context_indicators": ttp.context_indicators,
                            "source_chunk_index": i
                        })
                break # Success, exit retry loop
            except Exception as e:
                error_str = str(e)
                if "429" in error_str and "RESOURCE_EXHAUSTED" in error_str:
                    if attempt < max_retries - 1:
                        # If we have tried all keys on this iteration, respect the cooldown before rotating again
                        if (attempt + 1) % len(key_manager.keys) == 0:
                            if current_model == "gemini-2.5-flash":
                                print(f"\n⚠️ All keys rate limited for Flash. Falling back to Gemini 2.5 Flash Lite...")
                                current_model = "gemini-2.5-flash-lite"
                            else:
                                delay_match = re.search(r"'retryDelay':\s*'(\d+)\w*'", error_str)
                                delay = int(delay_match.group(1)) + 1 if delay_match else 60
                                print(f"\n⏳ All keys currently rate limited on Lite. Waiting {delay}s before continuing rotation...")
                                time.sleep(delay)
                        
                        # Rotate the key and instantiate a fresh Client
                        new_key = key_manager.rotate_key()
                        client = genai.Client(api_key=new_key)
                        time.sleep(0.5) # Tiny internal API pad
                    else:
                        print(f"\n⚠️ Max retries reached for chunk {i} due to rate limits across all keys.")
                        break
                else:
                    if attempt < max_retries - 1:
                        print(f"\n⚠️ Non-rate-limit error on chunk {i} (Attempt {attempt+1}): {e} \nRetrying...")
                        time.sleep(2)
                    else:
                        print(f"\n⚠️ Max retries reached or unrecoverable error extracting from chunk {i}: {e}")
                        break
            
    # 4. Save Final Output
    print("\n--- Phase 4: Finalizing Output ---")
    os.makedirs(FINAL_REPORTS_DIR, exist_ok=True)
    
    if not output_path:
        base_name = os.path.basename(pdf_path).replace(".pdf", "").replace(".PDF", "")
        output_path = os.path.join(FINAL_REPORTS_DIR, f"{base_name}_extracted_ttps.json")
        
    final_report = {
        "source_report": pdf_path,
        "total_chunks_analyzed": len(chunks),
        "total_ttps_found": len(all_ttps),
        "extracted_ttps": all_ttps
    }
    
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(final_report, f, indent=4, ensure_ascii=False)
        
    print(f"✅ Analysis complete! Found {len(all_ttps)} discrete behaviors.")
    print(f"📁 Report saved to: {output_path}")
    return output_path

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Automated MITRE ATT&CK extraction from CTI reports.")
    parser.add_argument("pdf", type=str, help="Path to the PDF threat report to analyze.")
    parser.add_argument("--output", type=str, help="Path to save the final JSON report.", default=None)
    args = parser.parse_args()
    
    if os.path.exists(args.pdf):
        analyze_report(args.pdf, args.output)
    else:
        print(f"❌ Target PDF not found: {args.pdf}")
