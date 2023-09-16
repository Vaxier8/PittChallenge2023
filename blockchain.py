import datetime
import json
import hashlib
from flask import Flask, jsonify, request, render_template
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

app = Flask(__name__)

blockchain = Blockchain()
from werkzeug.utils import secure_filename
import os

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'json'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Check if the file has an allowed extension
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/process_file', methods=['POST'])
def process_file():
    # check if the post request has the file part
    if 'file' not in request.files:
        return jsonify({"message": "No file part"}), 400

    file = request.files['file']

    # if user does not select file, browser may submit an empty part without filename
    if file.filename == '':
        return jsonify({"message": "No selected file"}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        with open(file_path, 'r') as f:
            data = json.load(f)

            # Assuming data is a list of patient dictionaries
            for patient in data:
                required_fields = ["subject_id", "gender", "drug", "care_type", "diagnoses"]

                # If all required fields exist, mine a block with the patient data
                if all(field in patient for field in required_fields):
                    previous_block = blockchain.get_previous_block()
                    previous_proof = previous_block['proof']
                    proof = blockchain.proof_of_work(previous_proof)
                    previous_hash = blockchain.hash(previous_block)

                    block = blockchain.create_blockchain(proof, previous_hash)

                    # Add patient details to the block
                    block["patient_data"] = patient

        os.remove(file_path)  # delete the file after processing
        
        return jsonify({"message": "Processed and added data to blockchain"}), 200
    else:
        return jsonify({"message": "Invalid file type"}), 400


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/mine_block', methods=['POST'])
def mine_block():
    # Get patient details from JSON input
    patient_data = request.json

    # Validate if required fields exist
    required_fields = ["subject_id", "gender", "drug", "care_type", "diagnoses"]
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

    block = blockchain.create_blockchain(proof, previous_hash, patient_data=patient)

    
    # Add patient details to the block
    block["patient_data"] = patient_data

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

app.run(host='0.0.0.0', port=5000)


#Mine_block
#get_chain


#subject_id, gender, drug
#care_type, diagnoses 