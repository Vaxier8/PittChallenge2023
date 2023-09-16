import os
import json
import re
import fitz
from collections import defaultdict


def extract_data_from_pdf(file_path):
    doc = fitz.open(file_path)
    text = ""

    for page in doc:
        text += page.get_text()

    text = text.replace('\ufb02', 'fl')

    data = {
        "subject_id": None,
        "PRESCRIPTION": [],
        "DIAGNOSES": []
    }

    subject_id_synonyms = ["Subject Id", "Patient Id", "Subject Identifier"]
    drug_name_synonyms = ["Drug Name", "Medication Name", "Prescription Name"]
    diagnosis_synonyms = ["Diagnosis", "Diagnosis Name", "Disease Name"]

    for synonym in subject_id_synonyms:
        subject_id_match = re.search(fr'{synonym}:\s*(\d+)', text)
        if subject_id_match:
            data["subject_id"] = int(subject_id_match.group(1))
            break

    for synonym in drug_name_synonyms:
        drug_name_matches = re.findall(fr'{synonym}:\s*([^:\n]+)', text)
        for match in drug_name_matches:
            data["PRESCRIPTION"].append({"drug_name": match.strip()})

    for synonym in diagnosis_synonyms:
        diagnosis_matches = re.findall(fr'{synonym}:\s*([^:\n]+)', text)
        for match in diagnosis_matches:
            diagnosis_data = {
                "diagnosis": match.strip(),
                "icd9_code": None
            }
            data["DIAGNOSES"].append(diagnosis_data)

    return data


def save_to_json(data, output_file):
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=4)


def main(pdf_dir, output_file):
    all_data = defaultdict(
        lambda: {"subject_id": None, "PRESCRIPTION": [], "DIAGNOSES": []})

    for root, dirs, files in os.walk(pdf_dir):
        for file in files:
            if file.endswith(".pdf"):
                file_path = os.path.join(root, file)
                data = extract_data_from_pdf(file_path)

                if data["subject_id"] is not None:
                    subject_id = data["subject_id"]
                    all_data[subject_id]["subject_id"] = subject_id
                    all_data[subject_id]["PRESCRIPTION"].extend(
                        data["PRESCRIPTION"])
                    all_data[subject_id]["DIAGNOSES"].extend(data["DIAGNOSES"])

    all_data = dict(all_data)
    save_to_json(list(all_data.values()), output_file)


# Usage
main('pdfDir', 'output.json')
