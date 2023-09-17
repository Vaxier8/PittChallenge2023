# PittChallenge2023 - Governance and Ethics in AI
## Overview

This repository contains our solution for the Pitt Challenge 2023, focusing on the topic of "Governance and Ethics in AI". Our aim is to ensure accountability and safety for private patient information in the healthcare domain.
## Features
### PDF Processing:

    Extract patient-related information from PDFs using regular expressions.
    Identify key patient details such as drug names, diagnoses, and subject IDs.
    Convert extracted data into a structured JSON format for further processing.

### Blockchain:

    Implement a basic blockchain structure to store patient data.
    Mine new blocks containing encrypted patient data.
    Validate the integrity of the blockchain using proof-of-work and hash functions.
    Ensure tamper-proof storage of patient data.

### Encryption:

    Generate unique encryption keys for each patient's data.
    Encrypt patient data using the Fernet symmetric encryption method from the cryptography library.
    Store encrypted data in the blockchain, ensuring data privacy.

### Trained Model And The Idea of AI:

    Automatically flag suspicious or inconsistent data entries based on the model's predictions.
    AI could be utilized through API's and access medical information in a secure and opt-in manner.

### Flask Web Application:

    User-friendly interface for uploading patient data in PDF format.
    Display blockchain contents and allow users to mine new blocks with patient data.
    Provide decryption functionality to retrieve original patient data from the blockchain.
    Intuitive error messages and data validation feedback.

### Data Validation:

    Validate drug names against a known dataset to ensure accuracy.
    Flag suspicious or inconsistent data entries for review.
    Utilize AI-driven validation to enhance data reliability.

### How to Use

    Run the Flask application using python blockchain.py.
    Access the web application at http://localhost:5000.
    Upload patient data in PDF format.
    Mine blocks with patient data and retrieve data using the provided encryption key.

### Judging Criteria:

    Technical Complexity: Comprehensive solution combining PDF processing, blockchain, encryption, AI, and web application development.
    Problem Definition: Addresses the challenge of ensuring data privacy in healthcare.
    Creativity: Novel approach of combining blockchain, encryption, and AI for data security.
    Feasibility: Practical solution using established technologies.
    Value: Significant market potential given the importance of data privacy in healthcare.

### Challenge Topic:

Artificial Intelligence is increasingly becoming more involved in healthcare. Our challenge was to find ways to protect patient’s private information and ensure good use of technology for the benefit of all.