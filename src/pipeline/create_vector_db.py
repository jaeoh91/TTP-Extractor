import json
import os
from langchain_core.documents import Document
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import Chroma

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data")
INPUT_FILE = os.path.join(DATA_DIR, "mitre_data", "parsed_techniques.json")
VECTOR_DB_DIR = os.path.join(DATA_DIR, "vector_db")

def load_techniques():
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def main():
    print("Loading parsed techniques...")
    techniques = load_techniques()
    
    documents = []
    for tech in techniques:
        # Combine name and description for richer embeddings
        # This helps the retriever match against both title keywords and behavioral summaries
        content = f"Technique: {tech['name']}\n\nDescription: {tech['description']}"
        
        metadata = {
            "t_id": tech.get("t_id", "UNKNOWN"),
            "name": tech.get("name", "UNKNOWN"),
            "is_subtechnique": str(tech.get("is_subtechnique", False)) # Ensure boolean is stringified or Chroma complains
        }
        
        # Ensure no None types in metadata 
        metadata = {k: v for k, v in metadata.items() if v is not None}
        
        doc = Document(page_content=content, metadata=metadata)
        documents.append(doc)
        
    print(f"Prepared {len(documents)} documents for embedding.")
    
    # Initialize the embedding model
    print("Initializing embedding model (all-MiniLM-L6-v2)...")
    embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
    
    # Create the vector store
    print(f"Creating Chroma vector database at {VECTOR_DB_DIR}...")
    print("This may take a minute or two as it embeds all techniques...")
    
    vectorstore = Chroma.from_documents(
        documents=documents,
        embedding=embeddings,
        persist_directory=VECTOR_DB_DIR
    )
    
    print("✅ Vector database created and persisted successfully!")
    print(f"Database located at: {VECTOR_DB_DIR}")

if __name__ == "__main__":
    main()
