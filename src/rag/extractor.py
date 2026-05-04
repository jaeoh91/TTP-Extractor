import os
import json
from typing import List
from pydantic import BaseModel, Field
from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import HuggingFaceEmbeddings
from google import genai
from google.genai import types

# Configuration Constants
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data")
VECTOR_DB_DIR = os.path.join(DATA_DIR, "vector_db")

# ---------------------------------------------------------
# Phase 3 Enhancements: Pydantic Structured Outputs
# ---------------------------------------------------------

class ExtractedTTP(BaseModel):
    t_id: str = Field(description="The exact MITRE ATT&CK Technique ID (e.g., T1059.001)")
    name: str = Field(description="The name of the technique")
    context_indicators: str = Field(description="Context and related indicators detailing exactly how the TTP was used by the threat actor in the text, useful for a CTI analyst.")

class ExtractionResult(BaseModel):
    contains_behavior: bool = Field(description="True if the text contains malicious actor behavior, False otherwise")
    ttps: List[ExtractedTTP] = Field(default_factory=list, description="List of MITRE ATT&CK techniques identified")

# ---------------------------------------------------------
# Orchestration Logic
# ---------------------------------------------------------

import chromadb

def get_vector_store():
    """Loads the Chroma vector database built in Phase 2."""
    embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
    # Use explicit Settings object to prevent Chroma singleton setting conflicts in Streamlit
    client_settings = chromadb.config.Settings(anonymized_telemetry=False)
    return Chroma(persist_directory=VECTOR_DB_DIR, embedding_function=embeddings, client_settings=client_settings)

def extract_ttps(chunk: str, vector_store, llm_client, model_name: str = "gemini-2.5-flash") -> ExtractionResult:
    """
    Retrieves context from ChromaDB and extracts structured TTPs from a text chunk.
    """
    # 1. Retrieve Candidate Techniques 
    # We fetch the top 5 most semantically similar techniques from our ATT&CK DB
    retrieved_docs = vector_store.similarity_search(chunk, k=5)
    
    context_str = "MITRE ATT&CK CANDIDATES:\n"
    for doc in retrieved_docs:
        # doc.page_content has both Technique Name and Description
        context_str += f"- [{doc.metadata.get('t_id')}] {doc.page_content}\n"
    
    # 2. Extract Structure via LLM (The 'G' in RAG)
    prompt = f"""
    You are a senior Cyber Threat Intelligence (CTI) analyst. 
    Your task is to analyze the following report excerpt and map attacker behaviors to the provided MITRE ATT&CK candidates.
    Only map behaviors if there is explicit evidence in the excerpt. Do not hallucinate techniques.
    
    REPORT EXCERPT:
    {chunk}
    
    {context_str}
    """
    
    # Use Google GenAI native structured output to strictly enforce the Pydantic schema
    response = llm_client.models.generate_content(
        model=model_name, 
        contents=f"System: You carefully analyze text for cyber threat behaviors and output strictly constrained JSON.\n\nUser: {prompt}",
        config=types.GenerateContentConfig(
            response_mime_type="application/json",
            response_schema=ExtractionResult,
            temperature=0.1,
            max_output_tokens=8192,
        )
    )
    
    return ExtractionResult.model_validate_json(response.text)

if __name__ == "__main__":
    
    print("Loading Vector DB...")
    db = get_vector_store()
    
    api_key = os.environ.get("GEMINI_API_KEY", "dummy-key")
    
    # Initialize the native Google GenAI client
    client = genai.Client(api_key=api_key)
    
    dummy_chunk = "The threat actors downloaded a heavily obfuscated PowerShell script using bitsadmin.exe. They then used this script to dump credentials from LSASS memory."
    
    print(f"\nTesting extraction on chunk:\n'{dummy_chunk}'\n")
    
    if api_key == "dummy-key":
        print("Waiting to run extraction... GEMINI_API_KEY is not set.")
        print("Export your API key (export GEMINI_API_KEY='your_key') to see it in action,")
        print("or point the instructor client to a local Ollama server.")
    else:
        try:
            res = extract_ttps(dummy_chunk, db, client)
            print("EXTRACTION RESULT (Validated JSON):")
            print(res.model_dump_json(indent=2))
        except Exception as e:
            print(f"Extraction test failed: {e}")
