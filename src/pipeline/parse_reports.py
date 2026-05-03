import os
import json
import argparse
from pathlib import Path
from docling.document_converter import DocumentConverter, PdfFormatOption
from docling.datamodel.pipeline_options import PdfPipelineOptions
from docling.datamodel.base_models import InputFormat
from langchain.text_splitter import RecursiveCharacterTextSplitter

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data")
RAW_REPORTS_DIR = os.path.join(DATA_DIR, "raw_reports")
PARSED_CHUNKS_DIR = os.path.join(DATA_DIR, "parsed_chunks")

def parse_and_chunk_pdf(pdf_path: str, chunk_size: int = 1000, chunk_overlap: int = 200):
    print(f"Parsing PDF: {pdf_path}")
    
    # 1. Parse with Docling
    # Docling cleanly handles multi-column layouts, tables, and avoids arbitrary header/footer injections
    # We disable OCR to avoid RapidOCR permission errors on Streamlit Cloud and speed up extraction.
    # CTI reports are generally primarily text-based PDFs.
    pipeline_options = PdfPipelineOptions()
    pipeline_options.do_ocr = False
    
    converter = DocumentConverter(
        format_options={InputFormat.PDF: PdfFormatOption(pipeline_options=pipeline_options)}
    )
    result = converter.convert(pdf_path)
    
    # We export to markdown to retain structural semantics (headings, lists, code blocks)
    full_text = result.document.export_to_markdown()
    
    print(f"Extracted {len(full_text)} characters. Chunking...")
    
    # 2. Chunk with LangChain
    # In CTI terms, behaviors are often described in paragraphs. We want paragraph-level semantic blocks.
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
        separators=["\n\n", "\n", ".", " ", ""]
    )
    
    chunks = text_splitter.split_text(full_text)
    print(f"Created {len(chunks)} chunks.")
    
    # 3. Save chunks
    base_name = Path(pdf_path).stem
    output_file = os.path.join(PARSED_CHUNKS_DIR, f"{base_name}_chunks.json")
    
    # Structure the output for our RAG pipeline
    output_data = {
        "source_file": os.path.basename(pdf_path),
        "total_chunks": len(chunks),
        "chunks": chunks
    }
    
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=4, ensure_ascii=False)
        
    print(f"✅ Saved chunks to {output_file}")
    return output_file

def main():
    os.makedirs(RAW_REPORTS_DIR, exist_ok=True)
    os.makedirs(PARSED_CHUNKS_DIR, exist_ok=True)
    
    parser = argparse.ArgumentParser(description="Parse PDF threat reports and chunk them for RAG.")
    parser.add_argument("--file", type=str, help="Path to a specific PDF file to parse.")
    parser.add_argument("--batch", action="store_true", help="Process all PDFs in the raw_reports directory.")
    parser.add_argument("--chunk-size", type=int, default=1000, help="Max chunk size in characters.")
    parser.add_argument("--overlap", type=int, default=200, help="Overlap between chunks in characters.")
    
    args = parser.parse_args()
    
    if args.file:
        if os.path.exists(args.file):
            parse_and_chunk_pdf(args.file, args.chunk_size, args.overlap)
        else:
            print(f"❌ File not found: {args.file}")
    
    elif args.batch:
        pdf_files = [f for f in os.listdir(RAW_REPORTS_DIR) if f.endswith((".pdf", ".PDF"))]
        if not pdf_files:
            print(f"ℹ️ No PDFs found in {RAW_REPORTS_DIR}. Place CTI threat reports there first.")
            return
            
        for pdf in pdf_files:
            parse_and_chunk_pdf(os.path.join(RAW_REPORTS_DIR, pdf), args.chunk_size, args.overlap)
            
    else:
        print("💡 Please provide a PDF file or use the batch flag.")
        print("Usage:")
        print("  python src/pipeline/parse_reports.py --file my_report.pdf")
        print("  python src/pipeline/parse_reports.py --batch")

if __name__ == "__main__":
    main()
