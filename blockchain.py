import os
import json
import re
import fitz
import datetime
import hashlib
from flask import Flask, jsonify, request, render_template
from cryptography.fernet import Fernet
from werkzeug.utils import secure_filename
import tkinter as tk
from tkinter import filedialog

# --------------------------
# PDF Processing Functions
# --------------------------
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

def main(selected_pdfs, output_file):
    all_data = []
    for file_path in selected_pdfs:
        data = extract_data_from_pdf(file_path)
        all_data.append(data)
    save_to_json(all_data, output_file)

def extract_data_from_pdfs():
    selected_pdfs = select_pdf_files()
    if selected_pdfs:
        main(selected_pdfs, 'output.json')

def select_pdf_files():
    root = tk.Tk()
    root.withdraw()
    file_paths = filedialog.askopenfilenames(title="Select PDF Files", filetypes=[("PDF files", "*.pdf")])
    return file_paths


# --------------------------
# Blockchain Class & Methods
# --------------------------

class Blockchain:
    def __init__(self):
        self.chain = []
        self.create_blockchain(proof=1, previous_hash='0')

    def create_blockchain(self, proof, previous_hash, patient_data=None):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': str(datetime.datetime.now()),
            'proof': proof,
            'previous_hash': previous_hash
        }
        if patient_data:
            block['patient_data'] = patient_data  # Add patient details to the block

        self.chain.append(block)
        return block


    def get_previous_block(self):
        last_block = self.chain[-1]
        return last_block

    def proof_of_work(self, previous_proof):
        # miners proof submitted
        new_proof = 1
        # status of proof of work
        check_proof = False
        while check_proof is False:
            # problem and algorithm based off the previous proof and new proof
            hash_operation = hashlib.sha256(str(new_proof ** 2 - previous_proof ** 2).encode()).hexdigest()
            # check miners solution to problem, by using miners proof in cryptographic encryption
            # if miners proof results in 4 leading zero's in the hash operation, then:
            if hash_operation[:4] == '0000':
                check_proof = True
            else:
                # if miners solution is wrong, give mine another chance until correct
                new_proof += 1
        return new_proof
 
    # generate a hash of an entire block
    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()
 
    # check if the blockchain is valid
    def is_chain_valid(self, chain):
        # get the first block in the chain and it serves as the previous block
        previous_block = chain[0]
        # an index of the blocks in the chain for iteration
        block_index = 1
        while block_index < len(chain):
            # get the current block
            block = chain[block_index]
            # check if the current block link to previous block has is the same as the hash of the previous block
            if block["previous_hash"] != self.hash(previous_block):
                return False
 
            # get the previous proof from the previous block
            previous_proof = previous_block['proof']
 
            # get the current proof from the current block
            current_proof = block['proof']
 
            # run the proof data through the algorithm
            hash_operation = hashlib.sha256(str(current_proof ** 2 - previous_proof ** 2).encode()).hexdigest()
            # check if hash operation is invalid
            if hash_operation[:4] != '0000':
                return False
            # set the previous block to the current block after running validation on current block
            previous_block = block
            block_index += 1
        return True
blockchain = Blockchain()

# --------------------------
# Encryption/Decryption Functions
# --------------------------

def generate_key():
    """Generates a key for encryption and returns it."""
    return Fernet.generate_key()

def encrypt_data(data, key):
    """Encrypts the data using the provided key."""
    f = Fernet(key)
    encrypted_data = f.encrypt(json.dumps(data).encode())
    return encrypted_data.decode()

def decrypt_data(encrypted_data, key):
    """Decrypts the data using the provided key."""
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data.encode())
    return json.loads(decrypted_data.decode())

# --------------------------
# Flask App Configuration
# --------------------------

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'json'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# --------------------------
# Helper Functions for Flask
# --------------------------

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --------------------------
# Flask Routes
# --------------------------

@app.route('/process_file', methods=['POST'])
def process_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    uploaded_files = request.files.getlist('file')

    if not uploaded_files or uploaded_files[0].filename == '':
        return jsonify({"error": "No selected file"}), 400

    all_data = []

    # Open keys.txt to append keys and IDs
    with open('keys.txt', 'a') as key_file:
        for file in uploaded_files:
            filename = secure_filename(file.filename)
            file_path = os.path.join('uploads', filename)
            file.save(file_path)
            data = extract_data_from_pdf(file_path)
            all_data.append(data)
            
            # Generate a key and encrypt the data with it
            key = generate_key()
            encrypted_data = encrypt_data(data, key)
            
            # Write the subject ID and key to keys.txt
            subject_id = data['subject_id']  # Assuming 'SubjectID' is the field's name
            key_file.write(f"{subject_id}: {key.decode()}\n")
            
            # Mine a block with the encrypted data
            previous_block = blockchain.get_previous_block()
            previous_proof = previous_block['proof']
            proof = blockchain.proof_of_work(previous_proof)
            previous_hash = blockchain.hash(previous_block)
            block = blockchain.create_blockchain(proof, previous_hash, patient_data=encrypted_data)

    save_to_json(all_data, 'output.json')
    return jsonify({"message": "Files processed, encrypted, blocks mined, and keys saved successfully"})

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/mine_block', methods=['POST'])
def mine_block():
    # Get patient details from JSON input
    patient_data = request.json

    # Validate if required fields exist
    required_fields = ["subject_id", "gender", "drug", "care_type", "diagnoses"] # date of birth, percription
    if not all(field in patient_data for field in required_fields):
        response = {
            'message': 'Invalid input. All patient fields are required.'
        }
        return jsonify(response), 400

    # Proceed with mining a block with the patient details
    previous_block = blockchain.get_previous_block()
    previous_proof = previous_block['proof']
    proof = blockchain.proof_of_work(previous_proof)
    previous_hash = blockchain.hash(previous_block)


    response = {
        'message': 'Block mined with patient details!',
        'block': block
    }
    
    return jsonify(response), 200

@app.route('/get_chain', methods=['GET'])
def get_chain():
    response = {'chain': blockchain.chain,
                'length': len(blockchain.chain)}
    return jsonify(response), 200

@app.route('/get_patient_data', methods=['POST'])
def get_patient_data():
    key = request.form['key'].encode()  # Get the decryption key from the form
    subject_id = int(request.form['subject_id'])  # Convert SubjectID to integer

    # Iterate through the chain to find the patient's data
    for block in blockchain.chain:
        # Check if the block has patient data
        if 'patient_data' in block:
            try:
                decrypted_data = decrypt_data(block['patient_data'], key)
                if decrypted_data['subject_id'] == subject_id:
                    return jsonify(decrypted_data), 200
            except:
                # Decryption failed for this block, move to the next block
                continue

    return jsonify({"message": "Data not found or incorrect key"}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
