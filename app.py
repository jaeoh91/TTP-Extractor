import os
os.environ["ANONYMIZED_TELEMETRY"] = "False"
os.environ["TOKENIZERS_PARALLELISM"] = "false"

import streamlit as st
import json
import base64
import pandas as pd
import pypdfium2 as pdfium
import plotly.express as px
import os
import sys
from pathlib import Path
import textwrap

# Explicitly add the project root to sys.path so modules like src.pipeline are found reliably on cloud instances
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from main import analyze_report

st.set_page_config(page_title="TTP Extractor Visualizer", layout="wide")
st.title("TTP Extractor - MITRE ATT&CK Visualizer")

# --- UI: Upload Component ---
st.sidebar.header("1. Upload & Process PDF")
uploaded_file = st.sidebar.file_uploader("Upload a CTI PDF Report", type=["pdf"])
if uploaded_file is not None:
    if st.sidebar.button("Run Extraction Pipeline"):
        raw_dir = Path("data/raw_reports")
        raw_dir.mkdir(parents=True, exist_ok=True)
        pdf_path = raw_dir / uploaded_file.name
        
        # Save uploaded file
        with open(pdf_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        
        # Run pipeline
        with st.spinner(f"Extracting TTPs from {uploaded_file.name}... (Watch terminal for exact progress)"):
            try:
                output_file = analyze_report(str(pdf_path))
                if output_file and os.path.exists(output_file):
                    st.sidebar.success("Extraction complete! Reloading to show the new report...")
                    st.rerun()
                else:
                    st.sidebar.error("Analysis finished, but no output file was generated.")
            except Exception as e:
                st.sidebar.error(f"Error during extraction: {e}")

st.sidebar.divider()

# --- UI: View Component ---
st.sidebar.header("2. View Extracted TTPs")
report_dir = Path("data/final_reports")
if not report_dir.exists():
    st.error(f"Reports directory not found: {report_dir}")
    st.stop()

reports = list(report_dir.glob("*.json"))
if not reports:
    st.warning("No extracted reports found. Upload a PDF using the sidebar to run the pipeline.")
    st.stop()

selected_report = st.sidebar.selectbox("Select a generated report", reports, format_func=lambda x: x.name)

if selected_report:
    with open(selected_report, "r") as f:
        data = json.load(f)
    
    st.header(f"Report: {data.get('source_report', selected_report.name)}")
    
    col1, col2 = st.columns(2)
    col1.metric("Total Chunks Analyzed", data.get("total_chunks_analyzed", 0))
    col2.metric("Total TTPs Found", data.get("total_ttps_found", 0))
    
    # Load Tactics mappings
    tactics_map = {}
    parsed_tech_file = Path("data/mitre_data/parsed_techniques.json")
    if parsed_tech_file.exists():
        with open(parsed_tech_file, "r") as f:
            tech_data = json.load(f)
            for t in tech_data:
                tid = t.get("t_id")
                tactics = t.get("tactics", [])
                # Title case and format the tactics
                formatted_tactics = ", ".join([tac.replace("-", " ").title() for tac in tactics])
                if tid:
                    tactics_map[tid] = formatted_tactics
    
    ttps = data.get("extracted_ttps", [])
    if ttps:
        df = pd.DataFrame(ttps)
        
        # Apply Tactics
        df["tactic"] = df["t_id"].map(lambda x: tactics_map.get(x, "Unknown Tactic"))
        
        # Handle field renaming compatibility (supporting older JSON that had 'justification')
        context_col = "context_indicators" if "context_indicators" in df.columns else "justification"
        
        # Create tabs to display extraction vs original PDF
        tab1, tab2 = st.tabs(["Extracted Data & Visualizations", "Original PDF Preview"])
        
        with tab1:
            # Display raw data
            st.subheader("Extracted TTPs")
            st.dataframe(df[["tactic", "t_id", "name", context_col]], width='stretch')
            
            # Visualization
            st.subheader("TTP Frequency Visualization (Grouped by Tactic)")
            
            # Explode by Tactic if multiple tactics are mapped per technique, 
            # or we can just group by the concatenated strings, but exploding gives clearer counts.
            # Since we joined them with ', ', let's explode them for visualization purely
            df_vis = df.copy()
            df_vis["tactic"] = df_vis["tactic"].str.split(", ")
            df_vis = df_vis.explode("tactic")
            
            # Define canonical MITRE ATT&CK tactic order
            mitre_tactics = [
                "Reconnaissance", "Resource Development", "Initial Access", "Execution", 
                "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", 
                "Discovery", "Lateral Movement", "Collection", "Command And Control", 
                "Exfiltration", "Impact"
            ]
            
            # Count frequency of each T-ID and Tactic combination
            ttp_counts = df_vis.groupby(['tactic', 't_id', 'name']).size().reset_index(name='Count')
            
            # Apply custom order mapping for correct MITRE sequential timeline
            ttp_counts['tactic_order'] = ttp_counts['tactic'].map(lambda x: mitre_tactics.index(x) if x in mitre_tactics else 99)
            ttp_counts = ttp_counts.sort_values(['tactic_order', 't_id'])
            
            # Combine t_id and name for better labeling
            ttp_counts['technique_label'] = ttp_counts['t_id'] + ": " + ttp_counts['name']
            
            # Create a wrapped version for the treemap to fit better inside the blocks
            ttp_counts['technique_label_wrapped'] = ttp_counts['technique_label'].apply(lambda x: '<br>'.join(textwrap.wrap(x, width=20)))
            
            fig = px.bar(ttp_counts, x='technique_label', y='Count', color='tactic', 
                         title="Frequency of Extracted Techniques by Tactic", 
                         hover_data=['t_id', 'name', 'tactic'],
                         category_orders={'tactic': mitre_tactics},
                         color_discrete_sequence=px.colors.qualitative.Set2)
            
            # Make x-axis labels strictly vertical (-90 degrees) and increase the overall chart height generously so bars aren't cramped
            fig.update_layout(
                xaxis_tickangle=-90, 
                height=900,
                margin=dict(b=300) # Ensure enough bottom margin for the long vertical text
            )
                         
            # Optionally add a Treemap representation, using the wrapped labels
            fig_tree = px.treemap(ttp_counts, path=['tactic', 'technique_label_wrapped'], values='Count',
                                  title="Tactic to Technique Treemap")
                                  
            # Increase the font size for readability and expand the height of the treemap
            fig_tree.update_traces(textfont=dict(size=18))
            fig_tree.update_layout(height=700)
            
            st.plotly_chart(fig, use_container_width=True)
            st.plotly_chart(fig_tree, use_container_width=True)
            
        with tab2:
            st.subheader("Interactive PDF Viewer")
            source_pdf_name = data.get("source_report", selected_report.name.replace(".json", ".pdf"))
            # In case the source_report is stored as an absolute path, we just get the name
            source_pdf_name = Path(source_pdf_name).name
            pdf_path = Path("data/raw_reports") / source_pdf_name
            
            if pdf_path.exists():
                try:
                    # Render using the existing pypdfium2 library from docling
                    pdf = pdfium.PdfDocument(str(pdf_path))
                    
                    # Display each page as an image to guarantee visualization works exactly
                    for page_idx in range(len(pdf)):
                        page = pdf.get_page(page_idx)
                        pil_image = page.render(scale=2).to_pil()
                        st.image(pil_image, caption=f"Page {page_idx + 1}")
                except Exception as e:
                    st.error(f"Could not load the PDF for viewing. The file might be corrupted or in an unsupported format. Error: {e}")
                
                # Still provide the raw download
                with open(pdf_path, "rb") as f:
                    pdf_bytes = f.read()
                    
                st.download_button(
                    label="📥 Download Original PDF",
                    data=pdf_bytes,
                    file_name=source_pdf_name,
                    mime="application/pdf"
                )
            else:
                st.warning(f"The original PDF file '{source_pdf_name}' was not found in the 'data/raw_reports' directory. Ensure it is uploaded or present locally.")

