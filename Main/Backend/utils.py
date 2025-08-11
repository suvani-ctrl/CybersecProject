import json
import numpy as np
from fpdf import FPDF

def extract_api_names(json_path):
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if isinstance(data, list) and data:
            main_entry = data[0]
            if isinstance(main_entry, dict) and 'apis' in main_entry and isinstance(main_entry['apis'], list):
                apis = [api_call.get('api_name', '') for api_call in main_entry['apis'] if isinstance(api_call, dict) and 'api_name' in api_call]
                return ' '.join(apis)
        return None
    except Exception:
        return None

def extract_byte_features(filepath):
    try:
        byte_counts = np.zeros(256, dtype=int)
        with open(filepath, 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) <= 1:
                    continue
                bytes_line = parts[1:]
                for byte in bytes_line:
                    if byte == '??':
                        continue
                    try:
                        val = int(byte, 16)
                        byte_counts[val] += 1
                    except ValueError:
                        continue
        total = np.sum(byte_counts)
        return byte_counts / total if total > 0 else byte_counts
    except Exception:
        return None

def generate_pdf_report(entry, pdf_path):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Malware Analysis Report", ln=True, align='C')
    pdf.ln(10)
    for key, value in entry.items():
        pdf.multi_cell(0, 10, f"{key.capitalize()}: {value}")
    pdf.output(pdf_path)