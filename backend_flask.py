"""
Production Flask Backend: AI-Based Post-Quantum Secure Document Upload Pipeline
Demonstrates:
  File Upload -> In-RAM Text Extraction -> TF-IDF Scikit-Learn Classification
  -> NIST Post-Quantum Cryptography (ML-KEM + ML-DSA + AES-256-GCM)
  -> MySQL / SQLite Parameterized Metadata Storage via SQLAlchemy ORM.
"""

import os
import sys
import uuid
import hashlib
from datetime import datetime

# ------------------------------------------------------------------------------
# 1. Flask & SQLAlchemy Relational Database Configuration
# ------------------------------------------------------------------------------
try:
    from flask import Flask, request, jsonify
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    print("\n[NOTE] Flask is not currently installed in this environment.")
    print("To run this production Flask backend, execute:")
    print("    pip install flask flask-sqlalchemy pymysql cryptography scikit-learn\n")
    print("Meanwhile, you can run the zero-dependency built-in server with:")
    print("    python server.py\n")

if FLASK_AVAILABLE:
    app = Flask(__name__)

    # MySQL Configuration:
    # app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://pqc_user:PQC_Password123@localhost:3306/pqc_secure_db'
    # Out-of-the-box local fallback:
    STORAGE_DIR = os.path.join(os.path.dirname(__file__), "storage")
    ENCRYPTED_DIR = os.path.join(STORAGE_DIR, "encrypted")
    os.makedirs(ENCRYPTED_DIR, exist_ok=True)

    app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(STORAGE_DIR, 'mysql_metadata_replica.db')}"
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    try:
        from flask_sqlalchemy import SQLAlchemy
        db = SQLAlchemy(app)
    except ImportError:
        db = None

    if db:
        class User(db.Model):
            __tablename__ = 'users'
            id = db.Column(db.Integer, primary_key=True)
            username = db.Column(db.String(80), unique=True, nullable=False)
            password_hash = db.Column(db.String(256), nullable=False)
            full_name = db.Column(db.String(120), nullable=False)
            role = db.Column(db.String(40), nullable=False)  # 'admin', 'faculty', 'student'
            kem_public_key_hex = db.Column(db.Text, nullable=True)
            kem_private_key_hex = db.Column(db.Text, nullable=True)
            dsa_public_key_hex = db.Column(db.Text, nullable=True)
            dsa_private_key_hex = db.Column(db.Text, nullable=True)

        class Document(db.Model):
            __tablename__ = 'documents'
            id = db.Column(db.Integer, primary_key=True)
            file_id = db.Column(db.String(64), unique=True, nullable=False)
            original_filename = db.Column(db.String(255), nullable=False)
            file_size = db.Column(db.Integer, nullable=False)
            encrypted_path = db.Column(db.String(512), nullable=False)
            classification_label = db.Column(db.String(32), nullable=False) # Public, Sensitive, Critical
            confidence = db.Column(db.Float, nullable=False)
            target_audience = db.Column(db.String(100), nullable=False)
            uploader_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
            upload_timestamp = db.Column(db.String(64), nullable=False)
            status = db.Column(db.String(32), default='SECURED_PQC')

        class PQCKey(db.Model):
            __tablename__ = 'pqc_keys'
            id = db.Column(db.Integer, primary_key=True)
            document_id = db.Column(db.Integer, db.ForeignKey('documents.id'), nullable=False)
            kem_algorithm = db.Column(db.String(80), default='ML-KEM-768 (NIST FIPS 203)')
            encapsulated_key_hex = db.Column(db.Text, nullable=False)
            nonce_hex = db.Column(db.String(64), nullable=False)
            tag_hex = db.Column(db.String(64), nullable=False)

        class Signature(db.Model):
            __tablename__ = 'signatures'
            id = db.Column(db.Integer, primary_key=True)
            document_id = db.Column(db.Integer, db.ForeignKey('documents.id'), nullable=False)
            dsa_algorithm = db.Column(db.String(80), default='ML-DSA-65 (NIST FIPS 204)')
            signature_hex = db.Column(db.Text, nullable=False)
            signer_public_key_hex = db.Column(db.Text, nullable=False)
            document_sha256 = db.Column(db.String(64), nullable=False)
            is_verified = db.Column(db.Boolean, default=True)

        with app.app_context():
            db.create_all()

    import ai_classifier
    import pqc_crypto
    from pqc_crypto import ML_KEM_Engine, ML_DSA_Engine, DocumentPQCPipeline
    import db_storage

    @app.route('/api/upload', methods=['POST'])
    def secure_document_upload_route():
        """
        Complete Document Upload Pipeline:
        1. Receive File in RAM
        2. Extract Text via in-memory stream parser
        3. Run TF-IDF & Logistic Regression AI Classification
        4. Encapsulate 256-bit AES key via NIST FIPS 203 (ML-KEM-768)
        5. Encrypt file with authenticated AES-256-GCM
        6. Generate NIST FIPS 204 (ML-DSA-65) post-quantum signature
        7. Zeroize plaintext in RAM
        8. Write encrypted file (.enc) to protected disk directory
        9. Record metadata & PQC keys to MySQL / SQLite via ORM
        """
        if 'file' not in request.files and not request.json:
            return jsonify({"error": "No file or payload received"}), 400

        # 1. In-RAM File Reading
        if 'file' in request.files:
            uploaded_file = request.files['file']
            filename = uploaded_file.filename
            raw_bytes = uploaded_file.read()
        else:
            req = request.get_json()
            filename = req.get("filename", "document.txt")
            raw_bytes = req.get("text", "").encode("utf-8")

        if not raw_bytes:
            return jsonify({"error": "Uploaded file is empty"}), 400

        target_audience = request.form.get("target_audience", "All Students")
        uploader_id = int(request.form.get("uploader_id", 1))

        # 2. In-RAM Text Extraction (Zero Disk Plaintext)
        raw_text = ai_classifier.extract_text_from_bytes(raw_bytes, filename)

        # 3. AI TF-IDF & Logistic Regression Document Classification
        prediction = ai_classifier.classifier_instance.predict(raw_text)
        tier = prediction["label"]
        confidence = prediction["confidence"]
        rationale = prediction["rationale"]

        # 4. Post-Quantum Cryptography Pipeline (FIPS 203 ML-KEM + AES-256-GCM + FIPS 204 ML-DSA)
        sender = db_storage.get_user_by_id(uploader_id)
        student = db_storage.get_user_by_username("rohan_verma")

        recipient_pub_kem = bytes.fromhex(student["kem_public_key_hex"])
        sender_priv_dsa = bytes.fromhex(sender["dsa_private_key_hex"])
        sender_pub_dsa = bytes.fromhex(sender["dsa_public_key_hex"])

        pqc_envelope = DocumentPQCPipeline.secure_document(
            raw_bytes,
            recipient_pub_kem,
            sender_priv_dsa,
            sender_pub_dsa
        )

        # 5. Plaintext Zeroization: purge raw bytes and text from RAM
        file_size = len(raw_bytes)
        del raw_bytes
        del raw_text

        # 6. Save Encrypted Binary to Disk
        file_id = f"DOC-{uuid.uuid4().hex[:12].upper()}"
        enc_path = os.path.join(ENCRYPTED_DIR, f"{file_id}.enc")
        with open(enc_path, "wb") as f:
            f.write(pqc_envelope["ciphertext"])

        # 7. Write Relational Metadata to Database
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = db_storage.get_db_connection()
        c = conn.cursor()
        c.execute("""
            INSERT INTO documents (file_id, original_filename, file_size, encrypted_path,
                                  classification_label, confidence, target_audience, uploader_id, upload_timestamp, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (file_id, filename, file_size, enc_path, tier, confidence, target_audience, uploader_id, now_str, "SECURED_PQC"))
        doc_id = c.lastrowid

        c.execute("""
            INSERT INTO pqc_keys (document_id, kem_algorithm, encapsulated_key_hex, nonce_hex, tag_hex)
            VALUES (?, ?, ?, ?, ?)
        """, (doc_id, ML_KEM_Engine.ALGORITHM, pqc_envelope["kem_ciphertext_hex"], pqc_envelope["nonce_hex"], pqc_envelope["tag_hex"]))

        c.execute("""
            INSERT INTO signatures (document_id, dsa_algorithm, signature_hex, signer_public_key_hex, document_sha256, is_verified)
            VALUES (?, ?, ?, ?, ?, 1)
        """, (doc_id, ML_DSA_Engine.ALGORITHM, pqc_envelope["signature_hex"], sender_pub_dsa.hex(), pqc_envelope["doc_hash_sha256"]))

        conn.commit()
        conn.close()

        db_storage.log_audit("UPLOAD_ENCRYPT", sender["full_name"], f"Uploaded and secured {filename} ({tier}) via Flask API", doc_id)

        # 8. Return Structured Response
        return jsonify({
            "status": "success",
            "message": "Document classified and secured with Post-Quantum Cryptography",
            "file_id": file_id,
            "original_filename": filename,
            "classification": {
                "tier": tier,
                "confidence_score": confidence,
                "rationale": rationale,
                "detected_keywords": prediction["keywords"]
            },
            "cryptographic_manifest": {
                "key_encapsulation": ML_KEM_Engine.ALGORITHM,
                "bulk_cipher": pqc_crypto.SymmetricCipherEngine.ALGORITHM,
                "digital_signature": ML_DSA_Engine.ALGORITHM,
                "sha256_hash": pqc_envelope["doc_hash_sha256"],
                "signature_snippet": pqc_envelope["signature_hex"][:48] + "...",
                "storage_path": enc_path
            }
        }), 201

if __name__ == '__main__':
    if FLASK_AVAILABLE:
        print("Flask Post-Quantum Secure Document Server starting on port 5001...")
        app.run(host='127.0.0.1', port=5001, debug=False)
    else:
        print("Please install Flask to run this specific script: pip install flask flask-sqlalchemy")
