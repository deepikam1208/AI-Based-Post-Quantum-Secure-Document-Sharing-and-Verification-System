"""
Database Layer: Metadata & Cryptographic Storage Engine
Conforming to NIST PQC Architecture with Multi-Department & Role-Based Routing:
- users: Student, Teacher, and Administrator accounts with ML-KEM & ML-DSA keypairs
- sessions: Persistent multi-device session storage (survives server restarts)
- documents: Document metadata with target_department, target_semester, target_role
- pqc_keys: ML-KEM encapsulated keys, IV/nonce, AES-GCM tags
- signatures: ML-DSA post-quantum digital signatures and signer public keys
- audit_logs: Tamper-evident compliance tracking
"""

import os
import sqlite3
import hashlib
import json
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional
from pqc_crypto import ML_KEM_Engine, ML_DSA_Engine

DB_DIR = os.path.join(os.path.dirname(__file__), "storage")
DB_PATH = os.path.join(DB_DIR, "system_metadata.db")
ENCRYPTED_FILES_DIR = os.path.join(DB_DIR, "encrypted")

os.makedirs(DB_DIR, exist_ok=True)
os.makedirs(ENCRYPTED_FILES_DIR, exist_ok=True)


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password: str) -> str:
    salt = b"PQC_SECURE_SALT_2026"
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000).hex()


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name TEXT NOT NULL,
        role TEXT NOT NULL,          -- 'admin', 'faculty', 'student'
        department TEXT NOT NULL,    -- 'Computer Science', 'Electrical Engineering', etc.
        semester INTEGER,            -- 6, 4, etc. (None for faculty/admin)
        usn TEXT,                    -- University Seat Number for students
        kem_public_key_hex TEXT,     -- ML-KEM-768 Public Key (FIPS 203)
        kem_private_key_hex TEXT,    -- ML-KEM-768 Private Key
        dsa_public_key_hex TEXT,     -- ML-DSA-65 Public Key (FIPS 204)
        dsa_private_key_hex TEXT     -- ML-DSA-65 Private Key
    );

    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id)
    );

    CREATE TABLE IF NOT EXISTS documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_id TEXT UNIQUE NOT NULL,
        original_filename TEXT NOT NULL,
        file_size INTEGER NOT NULL,
        encrypted_path TEXT NOT NULL,
        classification_label TEXT NOT NULL, -- 'Public', 'Sensitive', 'Critical'
        confidence REAL NOT NULL,
        target_department TEXT NOT NULL,    -- 'All Departments', 'Computer Science', 'Electrical Engineering'
        target_semester INTEGER DEFAULT 0,  -- 0 = All Semesters, or 6, 4, etc.
        target_role TEXT DEFAULT 'student',  -- 'student', 'faculty', 'all'
        target_audience TEXT NOT NULL,      -- Human readable label
        uploader_id INTEGER NOT NULL,
        upload_timestamp TEXT NOT NULL,
        status TEXT NOT NULL,               -- 'SECURED_PQC', 'PUBLISHED', 'ARCHIVED'
        FOREIGN KEY (uploader_id) REFERENCES users (id)
    );

    CREATE TABLE IF NOT EXISTS pqc_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        document_id INTEGER NOT NULL,
        recipient_id INTEGER,               -- Target student / recipient user ID
        kem_algorithm TEXT NOT NULL,        -- 'ML-KEM-768 (NIST FIPS 203)'
        encapsulated_key_hex TEXT NOT NULL,
        nonce_hex TEXT NOT NULL,            -- AES-256-GCM 96-bit Nonce
        tag_hex TEXT NOT NULL,              -- AES-256-GCM 128-bit Tag
        FOREIGN KEY (document_id) REFERENCES documents (id),
        FOREIGN KEY (recipient_id) REFERENCES users (id)
    );

    CREATE TABLE IF NOT EXISTS signatures (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        document_id INTEGER NOT NULL,
        dsa_algorithm TEXT NOT NULL,        -- 'ML-DSA-65 (NIST FIPS 204)'
        signature_hex TEXT NOT NULL,
        signer_public_key_hex TEXT NOT NULL,
        document_sha256 TEXT NOT NULL,
        is_verified INTEGER DEFAULT 1,
        FOREIGN KEY (document_id) REFERENCES documents (id)
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        document_id INTEGER,
        action TEXT NOT NULL,
        actor_name TEXT NOT NULL,
        details TEXT NOT NULL,
        timestamp TEXT NOT NULL
    );
    """)

    users_to_seed = [
        {
            "username": "admin",
            "password": "admin123",
            "full_name": "Dr. V. Raman",
            "role": "admin",
            "department": "Examination Office",
            "semester": None,
            "usn": "STAFF-EXAM-01"
        },
        {
            "username": "prof_sharma",
            "password": "faculty123",
            "full_name": "Prof. A. Sharma",
            "role": "faculty",
            "department": "Computer Science",
            "semester": None,
            "usn": "FAC-CS-102"
        },
        {
            "username": "prof_rao",
            "password": "faculty123",
            "full_name": "Prof. K. Rao",
            "role": "faculty",
            "department": "Electrical Engineering",
            "semester": None,
            "usn": "FAC-EE-105"
        },
        {
            "username": "rohan_verma",
            "password": "student123",
            "full_name": "Rohan Verma",
            "role": "student",
            "department": "Computer Science",
            "semester": 6,
            "usn": "1CS23CS045"
        },
        {
            "username": "priya_nair",
            "password": "student123",
            "full_name": "Priya Nair",
            "role": "student",
            "department": "Electrical Engineering",
            "semester": 4,
            "usn": "1EE24EE012"
        },
        {
            "username": "aarav_mehta",
            "password": "student123",
            "full_name": "Aarav Mehta",
            "role": "student",
            "department": "Computer Science",
            "semester": 6,
            "usn": "1CS23CS001"
        }
    ]

    for u in users_to_seed:
        cursor.execute("SELECT id FROM users WHERE LOWER(username) = LOWER(?)", (u["username"],))
        row = cursor.fetchone()
        if not row:
            kem_pub, kem_priv = ML_KEM_Engine.generate_keypair()
            dsa_pub, dsa_priv = ML_DSA_Engine.generate_keypair()

            cursor.execute("""
                INSERT INTO users (
                    username, password_hash, full_name, role, department, semester, usn,
                    kem_public_key_hex, kem_private_key_hex, dsa_public_key_hex, dsa_private_key_hex
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                u["username"],
                hash_password(u["password"]),
                u["full_name"],
                u["role"],
                u["department"],
                u["semester"],
                u["usn"],
                kem_pub.hex(),
                kem_priv.hex(),
                dsa_pub.hex(),
                dsa_priv.hex()
            ))

    # Migration check for recipient_id in pqc_keys
    try:
        cursor.execute("ALTER TABLE pqc_keys ADD COLUMN recipient_id INTEGER")
    except Exception:
        pass

    conn.commit()
    conn.close()


# Persistent Multi-Device Session Storage
def create_session(user_id: int) -> str:
    """Creates a persistent session token saved in SQLite database."""
    token = f"pqc_sess_{uuid.uuid4().hex}"
    conn = get_db_connection()
    cursor = conn.cursor()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        INSERT INTO sessions (token, user_id, created_at)
        VALUES (?, ?, ?)
    """, (token, user_id, now_str))
    conn.commit()
    conn.close()
    return token


def get_user_by_session_token(token: str) -> Optional[Dict[str, Any]]:
    """Retrieves user profile for a given session token, surviving server restarts."""
    if not token:
        return None
    clean_token = token.strip()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT u.* FROM users u
        JOIN sessions s ON s.user_id = u.id
        WHERE s.token = ?
    """, (clean_token,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def delete_session(token: str):
    """Removes a session token upon logout."""
    if not token:
        return
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM sessions WHERE token = ?", (token.strip(),))
    conn.commit()
    conn.close()


def authenticate_user(login_identifier: str, password: str) -> Optional[Dict[str, Any]]:
    """Authenticates by username OR USN (case-insensitive) against PBKDF2 hash."""
    if not login_identifier or not password:
        return None

    clean_id = login_identifier.strip()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM users
        WHERE LOWER(username) = LOWER(?) OR (usn IS NOT NULL AND LOWER(usn) = LOWER(?))
    """, (clean_id, clean_id))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    user = dict(row)
    if user["password_hash"] == hash_password(password.strip()):
        return user
    return None


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    if not username:
        return None
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM users
        WHERE LOWER(username) = LOWER(?) OR (usn IS NOT NULL AND LOWER(usn) = LOWER(?))
    """, (username.strip(), username.strip()))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    if not user_id:
        return None
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def list_users() -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, full_name, role, department, semester, usn FROM users")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def log_audit(action: str, actor_name: str, details: str, document_id: Optional[int] = None):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO audit_logs (document_id, action, actor_name, details, timestamp)
        VALUES (?, ?, ?, ?, ?)
    """, (
        document_id,
        action,
        actor_name,
        details,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    conn.commit()
    conn.close()


def list_documents_for_user(user: Dict[str, Any]) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT d.*, u.full_name as uploader_name, u.role as uploader_role, u.department as uploader_dept,
               s.signature_hex, s.signer_public_key_hex, s.document_sha256,
               k.kem_algorithm
        FROM documents d
        JOIN users u ON d.uploader_id = u.id
        LEFT JOIN signatures s ON s.document_id = d.id
        LEFT JOIN pqc_keys k ON k.document_id = d.id
        ORDER BY d.id DESC
    """)
    rows = cursor.fetchall()
    conn.close()

    all_docs = [dict(r) for r in rows]
    filtered = []

    user_role = user["role"]
    user_dept = user.get("department", "")
    user_sem = user.get("semester")

    for d in all_docs:
        target_dept = d.get("target_department") or "All Departments"
        target_sem = d.get("target_semester", 0)
        target_role = d.get("target_role") or "student"
        tier = d.get("classification_label")
        uploader_id = d.get("uploader_id")

        if user_role == "admin":
            filtered.append(d)

        elif user_role == "faculty":
            if uploader_id == user["id"]:
                filtered.append(d)
            elif target_role in ["all", "faculty"] and (target_dept in ["All Departments", user_dept] or tier == "Public"):
                filtered.append(d)

        elif user_role == "student":
            dept_matches = (target_dept in ["All Departments", user_dept])
            sem_matches = (target_sem == 0 or target_sem == user_sem or tier == "Public")
            role_matches = (target_role in ["all", "student"])

            if dept_matches and sem_matches and role_matches:
                filtered.append(d)

    return filtered


def get_document_full_envelope(file_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT d.*, u.full_name as uploader_name, u.department as uploader_dept,
               k.kem_algorithm, k.encapsulated_key_hex, k.nonce_hex, k.tag_hex, k.recipient_id,
               s.dsa_algorithm, s.signature_hex, s.signer_public_key_hex, s.document_sha256
        FROM documents d
        JOIN users u ON d.uploader_id = u.id
        JOIN pqc_keys k ON k.document_id = d.id
        JOIN signatures s ON s.document_id = d.id
        WHERE d.file_id = ?
    """, (file_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


init_db()
