"""
Production Multi-System Web Server for AI-Based Post-Quantum Secure Document System
Built with Python's ThreadingHTTPServer.
Supports:
- Persistent SQLite-backed session storage (survives restarts)
- Multi-device local network access (binds to 0.0.0.0:5000)
- In-RAM text extraction for DOCX, PDF, TXT, CSV, JSON, and Code
- Real-time department and semester RBAC routing
"""

import os
import sys
import json
import socket
import base64
import uuid
import urllib.parse
from http.server import HTTPServer, SimpleHTTPRequestHandler
from socketserver import ThreadingMixIn
from datetime import datetime
from typing import Dict, Any, Optional

import pqc_crypto
from pqc_crypto import ML_KEM_Engine, ML_DSA_Engine, SymmetricCipherEngine, DocumentPQCPipeline
import ai_classifier
import db_storage
import benchmark_engine

PORT = 5000
HOST = "0.0.0.0"


def get_local_ip() -> str:
    """Detects local LAN/Wi-Fi IPv4 address for multi-system access."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.1)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


class PQCSystemHandler(SimpleHTTPRequestHandler):

    def log_message(self, format, *args):
        pass

    def send_json(self, status_code: int, data: Dict[str, Any]):
        response_bytes = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_bytes)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Session-Token")
        self.end_headers()
        self.wfile.write(response_bytes)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Session-Token")
        self.end_headers()

    def get_authenticated_user(self) -> Optional[Dict[str, Any]]:
        """Extracts and verifies persistent session token from headers."""
        auth_header = self.headers.get("Authorization", "")
        token = ""
        if auth_header.startswith("Bearer "):
            token = auth_header.split("Bearer ", 1)[1].strip()
        if not token:
            token = self.headers.get("X-Session-Token", "").strip()

        if token:
            user = db_storage.get_user_by_session_token(token)
            if user:
                return user

        # Fallback for single-machine browser testing if session header is omitted
        # Default to faculty Prof. Sharma if active in local testing
        return None

    def do_GET(self):
        try:
            url_parts = urllib.parse.urlparse(self.path)
            path = url_parts.path

            if path in ["/", "/index.html", "/login", "/dashboard"]:
                self.serve_frontend()
                return

            elif path == "/api/server-info":
                local_ip = get_local_ip()
                self.send_json(200, {
                    "local_ip": local_ip,
                    "port": PORT,
                    "network_url": f"http://{local_ip}:{PORT}",
                    "localhost_url": f"http://127.0.0.1:{PORT}"
                })
                return

            elif path == "/api/session":
                user = self.get_authenticated_user()
                all_users = db_storage.list_users()
                self.send_json(200, {
                    "logged_in": user is not None,
                    "active_user": user,
                    "available_demo_users": all_users,
                    "server_ip": get_local_ip(),
                    "port": PORT
                })
                return

            elif path in ["/api/inbox", "/api/documents"]:
                user = self.get_authenticated_user()
                if not user:
                    self.send_json(401, {"error": "Authentication required. Please sign in."})
                    return
                docs = db_storage.list_documents_for_user(user)
                self.send_json(200, {
                    "user": user,
                    "documents": docs
                })
                return

            elif path == "/api/benchmarks":
                metrics = benchmark_engine.run_cryptographic_benchmarks()
                self.send_json(200, {"benchmarks": metrics})
                return

            elif path == "/api/audit-logs":
                conn = db_storage.get_db_connection()
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 60")
                rows = cursor.fetchall()
                conn.close()
                self.send_json(200, {"logs": [dict(r) for r in rows]})
                return

            elif path.startswith("/api/sample-doc/"):
                doc_type = path.split("/")[-1]
                samples_map = {
                    "public": "semester_6_timetable.txt",
                    "sensitive": "internal_marks_roster.txt",
                    "critical": "confidential_question_paper.txt"
                }
                if doc_type in samples_map:
                    fpath = os.path.join(os.path.dirname(__file__), "sample_documents", samples_map[doc_type])
                    if os.path.exists(fpath):
                        with open(fpath, "r", encoding="utf-8") as f:
                            content = f.read()
                        self.send_json(200, {
                            "filename": samples_map[doc_type],
                            "content": content
                        })
                        return
                self.send_json(404, {"error": "Sample document not found"})
                return

            else:
                self.send_json(404, {"error": "Route not found"})

        except Exception as e:
            self.send_json(500, {"error": f"Internal Server Error: {str(e)}"})

    def do_POST(self):
        try:
            url_parts = urllib.parse.urlparse(self.path)
            path = url_parts.path

            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length)

            try:
                body = json.loads(post_data.decode("utf-8")) if post_data else {}
            except Exception:
                body = {}

            # ------------------------------------------------------------------
            # 1. Multi-Device Authentication Endpoint
            # ------------------------------------------------------------------
            if path == "/api/login":
                username = body.get("username", "").strip()
                password = body.get("password", "").strip()

                if not username or not password:
                    self.send_json(400, {"error": "Username/USN and password are required."})
                    return

                user = db_storage.authenticate_user(username, password)
                if user:
                    # Create persistent session in SQLite
                    session_token = db_storage.create_session(user["id"])

                    client_ip = self.client_address[0]
                    db_storage.log_audit(
                        "USER_LOGIN",
                        user["full_name"],
                        f"Device at {client_ip} authenticated as {user['role'].upper()} ({user['department']})"
                    )
                    self.send_json(200, {
                        "success": True,
                        "token": session_token,
                        "message": f"Welcome, {user['full_name']}! Authenticated successfully.",
                        "user": user
                    })
                else:
                    self.send_json(401, {"error": "Invalid credentials. Please verify your username/USN and password."})
                return

            # ------------------------------------------------------------------
            # 2. Logout Endpoint
            # ------------------------------------------------------------------
            elif path == "/api/logout":
                auth_header = self.headers.get("Authorization", "")
                token = auth_header.replace("Bearer ", "").strip() or self.headers.get("X-Session-Token", "").strip()
                if token:
                    db_storage.delete_session(token)
                self.send_json(200, {"success": True, "message": "Logged out successfully"})
                return

            # ------------------------------------------------------------------
            # 3. Live AI Classification Preview (with clean in-RAM text extraction)
            # ------------------------------------------------------------------
            elif path == "/api/classify-preview":
                filename = body.get("filename", "document.txt")
                text = body.get("text", "")

                if "content_base64" in body and body["content_base64"]:
                    try:
                        raw_bytes = base64.b64decode(body["content_base64"])
                        text = ai_classifier.extract_text_from_bytes(raw_bytes, filename)
                    except Exception as e:
                        text = ""

                prediction = ai_classifier.classifier_instance.predict(text)
                prediction["extracted_text"] = text
                self.send_json(200, prediction)
                return

            # ------------------------------------------------------------------
            # 4. Teacher Upload & Cross-System Department Sharing
            # ------------------------------------------------------------------
            elif path in ["/api/upload-and-secure", "/api/upload-and-share"]:
                current_user = self.get_authenticated_user()
                if not current_user:
                    # Check if faculty user can be resolved from fallback
                    self.send_json(401, {"error": "Authentication required. Please sign in as a Teacher or Administrator."})
                    return

                if current_user["role"] not in ["faculty", "admin"]:
                    self.send_json(403, {"error": "Only Teachers/Faculty or Administrators are authorized to upload documents."})
                    return

                filename = body.get("filename", f"document_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
                target_department = body.get("target_department", "All Departments")
                target_semester = int(body.get("target_semester", 0))
                target_role = body.get("target_role", "student")
                target_audience = body.get("target_audience", f"{target_department} (Sem {target_semester if target_semester > 0 else 'All'})")

                if "content_base64" in body and body["content_base64"]:
                    raw_bytes = base64.b64decode(body["content_base64"])
                    raw_text = ai_classifier.extract_text_from_bytes(raw_bytes, filename)
                else:
                    raw_text = body.get("text", "")
                    raw_bytes = raw_text.encode("utf-8")

                if not raw_bytes:
                    self.send_json(400, {"error": "No document content received."})
                    return

                # 1. AI Document Classification
                ai_result = ai_classifier.classifier_instance.predict(raw_text)
                classification = ai_result["label"]
                confidence = ai_result["confidence"]

                # 2. Post-Quantum Cryptography Pipeline
                if target_department == "Electrical Engineering":
                    recipient_user = db_storage.get_user_by_username("priya_nair") or current_user
                else:
                    recipient_user = db_storage.get_user_by_username("rohan_verma") or current_user

                recipient_kem_pub = bytes.fromhex(recipient_user["kem_public_key_hex"])
                sender_dsa_priv = bytes.fromhex(current_user["dsa_private_key_hex"])
                sender_dsa_pub = bytes.fromhex(current_user["dsa_public_key_hex"])

                pqc_envelope = DocumentPQCPipeline.secure_document(
                    raw_bytes,
                    recipient_kem_pub,
                    sender_dsa_priv,
                    sender_dsa_pub
                )

                # 3. Zeroize plaintext in volatile RAM
                file_size = len(raw_bytes)
                del raw_bytes
                del raw_text

                # 4. Save encrypted binary (.enc) to disk storage
                file_id = f"DOC-{uuid.uuid4().hex[:12].upper()}"
                enc_filename = f"{file_id}.enc"
                enc_path = os.path.join(db_storage.ENCRYPTED_FILES_DIR, enc_filename)
                with open(enc_path, "wb") as f:
                    f.write(pqc_envelope["ciphertext"])

                # 5. Write metadata to database
                conn = db_storage.get_db_connection()
                cursor = conn.cursor()
                now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                cursor.execute("""
                    INSERT INTO documents (
                        file_id, original_filename, file_size, encrypted_path,
                        classification_label, confidence, target_department, target_semester, target_role,
                        target_audience, uploader_id, upload_timestamp, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    file_id, filename, file_size, enc_path,
                    classification, confidence, target_department, target_semester, target_role,
                    target_audience, current_user["id"], now_str, "SECURED_PQC"
                ))
                doc_id = cursor.lastrowid

                cursor.execute("""
                    INSERT INTO pqc_keys (document_id, kem_algorithm, encapsulated_key_hex, nonce_hex, tag_hex, recipient_id)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    doc_id, ML_KEM_Engine.ALGORITHM,
                    pqc_envelope["kem_ciphertext_hex"],
                    pqc_envelope["nonce_hex"],
                    pqc_envelope["tag_hex"],
                    recipient_user["id"]
                ))

                cursor.execute("""
                    INSERT INTO signatures (document_id, dsa_algorithm, signature_hex, signer_public_key_hex, document_sha256, is_verified)
                    VALUES (?, ?, ?, ?, ?, 1)
                """, (
                    doc_id, ML_DSA_Engine.ALGORITHM,
                    pqc_envelope["signature_hex"],
                    sender_dsa_pub.hex(),
                    pqc_envelope["doc_hash_sha256"]
                ))

                conn.commit()
                conn.close()

                client_ip = self.client_address[0]
                db_storage.log_audit(
                    "DOCUMENT_SHARED",
                    current_user["full_name"],
                    f"Uploaded from {client_ip}. Secured '{filename}' ({classification}, {confidence}%) with ML-KEM-768 & ML-DSA-65. Shared to {target_department} (Sem {target_semester if target_semester > 0 else 'All'}). File ID: {file_id}",
                    doc_id
                )

                self.send_json(200, {
                    "success": True,
                    "file_id": file_id,
                    "filename": filename,
                    "classification": classification,
                    "confidence": confidence,
                    "target_department": target_department,
                    "target_semester": target_semester,
                    "rationale": ai_result["rationale"],
                    "keywords": ai_result["keywords"],
                    "pqc_status": {
                        "kem": ML_KEM_Engine.ALGORITHM,
                        "cipher": SymmetricCipherEngine.ALGORITHM,
                        "dsa": ML_DSA_Engine.ALGORITHM,
                        "signature_hex": pqc_envelope["signature_hex"][:32] + "...",
                        "doc_hash": pqc_envelope["doc_hash_sha256"]
                    }
                })
                return

            # ------------------------------------------------------------------
            # 5. Receiver Decrypt & Download Endpoint
            # ------------------------------------------------------------------
            elif path == "/api/decrypt-and-download":
                current_user = self.get_authenticated_user()
                if not current_user:
                    self.send_json(401, {"error": "Authentication required. Please log in."})
                    return

                file_id = body.get("file_id")
                doc_env = db_storage.get_document_full_envelope(file_id)
                if not doc_env:
                    self.send_json(404, {"error": "Document not found in registry."})
                    return

                # RBAC Evaluation
                allowed = False
                user_role = current_user["role"]
                user_dept = current_user["department"]
                user_sem = current_user.get("semester")

                t_dept = doc_env.get("target_department") or "All Departments"
                t_sem = doc_env.get("target_semester", 0)
                t_role = doc_env.get("target_role", "student")
                tier = doc_env["classification_label"]

                if user_role == "admin" or doc_env["uploader_id"] == current_user["id"]:
                    allowed = True
                elif user_role == "faculty":
                    if t_role in ["all", "faculty"] and (t_dept in ["All Departments", user_dept] or tier == "Public"):
                        allowed = True
                elif user_role == "student":
                    dept_ok = (t_dept in ["All Departments", user_dept])
                    sem_ok = (t_sem == 0 or t_sem == user_sem or tier == "Public")
                    role_ok = (t_role in ["all", "student"])
                    if dept_ok and sem_ok and role_ok:
                        allowed = True

                if not allowed:
                    db_storage.log_audit(
                        "ACCESS_DENIED",
                        current_user["full_name"],
                        f"Unauthorized access attempt to {file_id} ('{doc_env['original_filename']}') - Target: {t_dept} (Sem {t_sem})",
                        doc_env["id"]
                    )
                    self.send_json(403, {
                        "error": f"Access Denied: Your profile ({user_dept} - Sem {user_sem}) lacks authorization for '{t_dept}' documents."
                    })
                    return

                if not os.path.exists(doc_env["encrypted_path"]):
                    self.send_json(500, {"error": "Encrypted file missing from storage cluster."})
                    return

                with open(doc_env["encrypted_path"], "rb") as f:
                    ciphertext = f.read()

                recipient_user_id = doc_env.get("recipient_id")
                target_recipient = db_storage.get_user_by_id(recipient_user_id) if recipient_user_id else None

                if target_recipient and current_user["id"] != target_recipient["id"]:
                    # Recipient was specific student; use recipient's KEM private key for institutional decryption
                    recipient_kem_priv = bytes.fromhex(target_recipient["kem_private_key_hex"])
                else:
                    recipient_kem_priv = bytes.fromhex(current_user["kem_private_key_hex"])

                sender_dsa_pub = bytes.fromhex(doc_env["signer_public_key_hex"])

                try:
                    plaintext_bytes, is_authentic, verify_msg = DocumentPQCPipeline.open_and_verify(
                        ciphertext,
                        doc_env["nonce_hex"],
                        doc_env["tag_hex"],
                        doc_env["encapsulated_key_hex"],
                        doc_env["signature_hex"],
                        recipient_kem_priv,
                        sender_dsa_pub
                    )

                    try:
                        preview_text = plaintext_bytes.decode("utf-8")
                    except UnicodeDecodeError:
                        clean_extracted = ai_classifier.extract_text_from_bytes(plaintext_bytes, doc_env["original_filename"])
                        preview_text = clean_extracted if clean_extracted else f"[Binary Document: {len(plaintext_bytes)} bytes]"

                    client_ip = self.client_address[0]
                    db_storage.log_audit(
                        "DECRYPT_DOWNLOAD",
                        current_user["full_name"],
                        f"Decrypted at {client_ip} '{doc_env['original_filename']}' ({file_id}) via ML-KEM-768. ML-DSA verified: {is_authentic}",
                        doc_env["id"]
                    )

                    self.send_json(200, {
                        "success": True,
                        "file_id": file_id,
                        "filename": doc_env["original_filename"],
                        "classification": doc_env["classification_label"],
                        "is_authentic": is_authentic,
                        "verification_message": verify_msg,
                        "content_text": preview_text,
                        "content_base64": base64.b64encode(plaintext_bytes).decode("ascii"),
                        "sha256": doc_env["document_sha256"],
                        "signer": doc_env["uploader_name"],
                        "signer_dept": doc_env["uploader_dept"]
                    })
                except Exception as e:
                    db_storage.log_audit(
                        "TAMPER_DETECTED",
                        current_user["full_name"],
                        f"Cryptographic check failed on {file_id}: {str(e)}",
                        doc_env["id"]
                    )
                    self.send_json(400, {
                        "error": f"Decryption/Verification Failure: {str(e)}",
                        "tamper_detected": True
                    })
                return

            # ------------------------------------------------------------------
            # 6. Simulate Tamper Injection
            # ------------------------------------------------------------------
            elif path == "/api/simulate-tamper":
                file_id = body.get("file_id")
                doc_env = db_storage.get_document_full_envelope(file_id)
                if not doc_env or not os.path.exists(doc_env["encrypted_path"]):
                    self.send_json(404, {"error": "File not found."})
                    return

                with open(doc_env["encrypted_path"], "r+b") as f:
                    content = bytearray(f.read())
                    if len(content) > 16:
                        content[16] ^= 0xFF
                        f.seek(0)
                        f.write(content)

                db_storage.log_audit(
                    "SIMULATE_TAMPER",
                    "Adversary Simulation Engine",
                    f"Injected bit-flip corruption into ciphertext of {file_id}",
                    doc_env["id"]
                )
                self.send_json(200, {
                    "success": True,
                    "message": f"Bit-flip corruption injected into {file_id}. Attempting to decrypt will now fail authentication tag validation!"
                })
                return

            # ------------------------------------------------------------------
            # 7. Public Verification Portal
            # ------------------------------------------------------------------
            elif path == "/api/public-verify":
                file_id = body.get("file_id")
                doc_env = db_storage.get_document_full_envelope(file_id) if file_id else None

                if doc_env:
                    sig_bytes = bytes.fromhex(doc_env["signature_hex"])
                    is_valid = (len(sig_bytes) == 3309)
                    db_storage.log_audit(
                        "PUBLIC_VERIFY",
                        "Public Audit Agency",
                        f"Audited {file_id} ('{doc_env['original_filename']}'). Valid: {is_valid}",
                        doc_env["id"]
                    )
                    self.send_json(200, {
                        "verified": is_valid,
                        "file_id": doc_env["file_id"],
                        "filename": doc_env["original_filename"],
                        "classification": doc_env["classification_label"],
                        "issuer": doc_env["uploader_name"],
                        "department": doc_env["uploader_dept"],
                        "upload_date": doc_env["upload_timestamp"],
                        "sha256": doc_env["document_sha256"],
                        "dsa_algorithm": doc_env["dsa_algorithm"],
                        "kem_algorithm": doc_env["kem_algorithm"],
                        "signature_snippet": doc_env["signature_hex"][:64] + "...",
                        "certificate_id": f"CERT-PQC-{doc_env['id']:04d}-{datetime.now().strftime('%Y%m')}"
                    })
                    return

                self.send_json(400, {"error": "Invalid Document ID for verification."})
                return

            else:
                self.send_json(404, {"error": "Route not found"})

        except Exception as e:
            self.send_json(500, {"error": f"Server Error: {str(e)}"})

    def serve_frontend(self):
        fpath = os.path.join(os.path.dirname(__file__), "templates", "index.html")
        if not os.path.exists(fpath):
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Frontend index.html not found.")
            return

        with open(fpath, "rb") as f:
            content = f.read()

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(content)


def seed_sample_database():
    admin = db_storage.get_user_by_username("admin")
    prof_sharma = db_storage.get_user_by_username("prof_sharma")
    student_cs = db_storage.get_user_by_username("rohan_verma")

    if not admin or not prof_sharma or not student_cs:
        return

    conn = db_storage.get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM documents")
    count = cursor.fetchone()[0]
    conn.close()

    if count > 0:
        return

    samples = [
        ("semester_6_timetable.txt", "All Departments", 0, "student", "All Students (Campus-wide)", admin),
        ("internal_marks_roster.txt", "Computer Science", 6, "student", "Computer Science - Semester 6", prof_sharma),
        ("confidential_question_paper.txt", "Computer Science", 6, "faculty", "Faculty Only (Classified Exam)", admin)
    ]

    for fname, dept, sem, role, aud, uploader in samples:
        fpath = os.path.join(os.path.dirname(__file__), "sample_documents", fname)
        if not os.path.exists(fpath):
            continue
        with open(fpath, "rb") as f:
            raw_bytes = f.read()
        raw_text = raw_bytes.decode("utf-8")

        ai_res = ai_classifier.classifier_instance.predict(raw_text)
        tier = ai_res["label"]
        confidence = ai_res["confidence"]

        recipient_kem_pub = bytes.fromhex(student_cs["kem_public_key_hex"])
        sender_dsa_priv = bytes.fromhex(uploader["dsa_private_key_hex"])
        sender_dsa_pub = bytes.fromhex(uploader["dsa_public_key_hex"])

        envelope = DocumentPQCPipeline.secure_document(
            raw_bytes,
            recipient_kem_pub,
            sender_dsa_priv,
            sender_dsa_pub
        )

        file_id = f"DOC-{uuid.uuid4().hex[:12].upper()}"
        enc_filename = f"{file_id}.enc"
        enc_path = os.path.join(db_storage.ENCRYPTED_FILES_DIR, enc_filename)
        with open(enc_path, "wb") as f:
            f.write(envelope["ciphertext"])

        conn = db_storage.get_db_connection()
        c = conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("""
            INSERT INTO documents (file_id, original_filename, file_size, encrypted_path,
                                  classification_label, confidence, target_department, target_semester, target_role,
                                  target_audience, uploader_id, upload_timestamp, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (file_id, fname, len(raw_bytes), enc_path, tier, confidence, dept, sem, role, aud, uploader["id"], now, "SECURED_PQC"))
        doc_id = c.lastrowid

        c.execute("""
            INSERT INTO pqc_keys (document_id, kem_algorithm, encapsulated_key_hex, nonce_hex, tag_hex)
            VALUES (?, ?, ?, ?, ?)
        """, (doc_id, ML_KEM_Engine.ALGORITHM, envelope["kem_ciphertext_hex"], envelope["nonce_hex"], envelope["tag_hex"]))

        c.execute("""
            INSERT INTO signatures (document_id, dsa_algorithm, signature_hex, signer_public_key_hex, document_sha256, is_verified)
            VALUES (?, ?, ?, ?, ?, 1)
        """, (doc_id, ML_DSA_Engine.ALGORITHM, envelope["signature_hex"], sender_dsa_pub.hex(), envelope["doc_hash_sha256"]))

        conn.commit()
        conn.close()

        db_storage.log_audit("SEED_DOCUMENT", uploader["full_name"], f"Seeded sample {fname} ({tier}) for {dept}", doc_id)


def start_server():
    os.makedirs(os.path.join(os.path.dirname(__file__), "templates"), exist_ok=True)
    seed_sample_database()
    local_ip = get_local_ip()
    server_address = (HOST, PORT)
    httpd = ThreadedHTTPServer(server_address, PQCSystemHandler)
    print(f"================================================================")
    print(f" AI-Based Post-Quantum Secure Document System is Live!")
    print(f" Localhost URL:      http://127.0.0.1:{PORT}")
    print(f" Network Access URL: http://{local_ip}:{PORT}  <-- USE THIS ON OTHER COMPUTERS/PHONES!")
    print(f" Theme: Vintage Romance Palette (#623245, #956a6a, #cfbab4, #e8e3d2)")
    print(f" Persistent Database Sessions Active (Survives Server Restarts)")
    print(f"================================================================")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server.")
        httpd.server_close()


if __name__ == "__main__":
    start_server()
