# TTP-Extractor
Automated MITRE ATT&CK extraction RAG pipeline for Cyber Threat Intelligence (CTI) reports.

This tool ingests PDF threat reports, chunks them, and leverages a Retrieval-Augmented Generation (RAG) pipeline powered by Google's Gemini models (currently gemini-2.5-flash, but any gemini model works) to automatically extract recognized MITRE ATT&CK Tactics, Techniques, and Procedures (TTPs) from unstructured text.

## Features
- Utilizes the `docling` package to **preserve document structure when parsing PDFs**
- Uses `ChromaDB` and `sentence-transformers` for local RAG against the MITRE STIX JSON dataset.
- Uses the structured output functionality built into Google GenAI models to emit **strictly typed JSON using Pydantic schemas**
-  Automatically cycles through a pool of Gemini API keys (for those of us too broke for credits...) and automatically handles rate limiting.
- Includes a Streamlit dashboard built with Plotly to visualize the frequency of extracted TTPs & other useful information for CTI teams

## Project Structure
```
TTP-Extractor/
├── data/
│   ├── raw_reports/       # Place your PDF reports to ingest here
│   └── final_reports/     # JSONs containing extracted ATT&CK TTPs will end up here
├── src/
│   ├── pipeline/          # Parsing, Chunking, and DB creation scripts
│   └── rag/               # LLM Extractor and Prompts
├── main.py                # Main orchestrator script
├── app.py                 # Streamlit Visualizer UI
├── requirements.txt       # Project dependencies
└── .env.example           # Example environment variables, please create your own!
```

## Setup & Installation

1. **Create your venv:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure env:**
   Create a `.env` file in the root directory and add your Google Gemini API keys (comma-separated for rotation).
   ```
   cp .env.example .env
   ```

## Usage

### 1. Extract TTPs
Run the extraction engine against a target PDF report:
```bash
python3 main.py data/raw_reports/TargetReport.pdf
```

### 2. Visualize Results
Launch the Streamlit dashboard to analyze the outputs:
```bash
streamlit run app.py
```
*This will open an interactive web app at `http://localhost:8501`.*
