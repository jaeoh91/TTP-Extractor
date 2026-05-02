import streamlit as st
import json
import pandas as pd
import plotly.express as px
import os
from pathlib import Path
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
                analyze_report(str(pdf_path))
                st.sidebar.success("Extraction complete! Report added to the dropdown below.")
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
        
        # Display raw data
        st.subheader("Extracted TTPs")
        st.dataframe(df[["tactic", "t_id", "name", context_col]], use_container_width=True)
        
        # Visualization
        st.subheader("TTP Frequency Visualization (Grouped by Tactic)")
        
        # Explode by Tactic if multiple tactics are mapped per technique, 
        # or we can just group by the concatenated strings, but exploding gives clearer counts.
        # Since we joined them with ', ', let's explode them for visualization purely
        df_vis = df.copy()
        df_vis["tactic"] = df_vis["tactic"].str.split(", ")
        df_vis = df_vis.explode("tactic")
        
        # Count frequency of each T-ID and Tactic combination
        ttp_counts = df_vis.groupby(['tactic', 't_id', 'name']).size().reset_index(name='Count')
        
        fig = px.bar(ttp_counts, x='t_id', y='Count', color='tactic', 
                     title="Frequency of Extracted Techniques by Tactic", 
                     hover_data=['name', 'tactic'],
                     category_orders={'tactic': sorted(ttp_counts['tactic'].unique())},
                     color_discrete_sequence=px.colors.qualitative.Set2)
                     
        # Optionally add a Treemap representation
        fig_tree = px.treemap(ttp_counts, path=['tactic', 't_id'], values='Count',
                              title="Tactic to Technique Treemap")
        
        st.plotly_chart(fig, use_container_width=True)
        st.plotly_chart(fig_tree, use_container_width=True)

