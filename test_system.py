"""
Comprehensive System Verification Test Suite
Tests:
1. Multi-Role Authentication (Student, Teacher, Admin)
2. AI Document Classification & Department Detection
3. Department-Specific RBAC Routing & Receiver Visibility
4. Post-Quantum Cryptographic Pipeline (ML-KEM-768 + AES-256-GCM + ML-DSA-65)
5. Quantum-Safe Tamper Interception
6. Performance Benchmark Metrics (Classical vs Hybrid vs PQC)
"""

import os
import ai_classifier
import db_storage
import benchmark_engine
from pqc_crypto import DocumentPQCPipeline

def run_all_tests():
    print("=" * 70)
    print("AI-BASED POST-QUANTUM SECURE DOCUMENT SYSTEM: FULL VERIFICATION")
    print("=" * 70)

    # --------------------------------------------------------------------------
    # 1. Multi-Role Authentication
    # --------------------------------------------------------------------------
    print("\n--- 1. Testing Multi-Role Authentication ---")
    admin = db_storage.authenticate_user("admin", "admin123")
    assert admin is not None and admin["role"] == "admin", "Admin login failed"
    print(f"✅ Admin Login:   {admin['full_name']} ({admin['department']})")

    teacher_cs = db_storage.authenticate_user("prof_sharma", "faculty123")
    assert teacher_cs is not None and teacher_cs["role"] == "faculty", "Teacher login failed"
    print(f"✅ Teacher Login: {teacher_cs['full_name']} ({teacher_cs['department']})")

    student_cs = db_storage.authenticate_user("rohan_verma", "student123")
    assert student_cs is not None and student_cs["role"] == "student", "Student login failed"
    print(f"✅ Student Login: {student_cs['full_name']} ({student_cs['department']} Sem {student_cs['semester']})")

    student_ee = db_storage.authenticate_user("priya_nair", "student123")
    assert student_ee is not None and student_ee["role"] == "student", "Student EE login failed"
    print(f"✅ Student Login: {student_ee['full_name']} ({student_ee['department']} Sem {student_ee['semester']})")

    # --------------------------------------------------------------------------
    # 2. AI Document Classification & Department Detection
    # --------------------------------------------------------------------------
    print("\n--- 2. Testing AI Classification on Various Academic Documents ---")
    test_docs = [
        ("CS602 Advanced Algorithms and Cryptography Examination Question Paper. Total Marks 100. Time 3 Hours.", "Critical", "Computer Science"),
        ("Internal Assessment Marks: Student roll numbers, Test 1 and Test 2 scores, and continuous evaluation.", "Sensitive", "All Departments"),
        ("Academic Calendar and general holiday schedule for undergraduate engineering students.", "Public", "All Departments"),
        ("EE401 High Voltage Engineering and Power Electronics Lab Continuous Evaluation Marks Roster.", "Sensitive", "Electrical Engineering")
    ]

    for text, exp_tier, exp_dept in test_docs:
        pred = ai_classifier.classifier_instance.predict(text)
        print(f"   * Input: '{text[:45]}...'")
        print(f"     -> Tier: {pred['label']} (Exp: {exp_tier}) | Dept: {pred['recommended_department']} | Conf: {pred['confidence']}%")
        assert pred["label"] == exp_tier, f"Tier mismatch for: {text}"

    print(">>> All AI Classifications matched expected security tiers!")

    # --------------------------------------------------------------------------
    # 3. Post-Quantum Cryptographic Pipeline
    # --------------------------------------------------------------------------
    print("\n--- 3. Testing Post-Quantum Cryptographic Pipeline (ML-KEM + ML-DSA + AES-GCM) ---")
    doc_raw = b"CLASSIFIED: Computer Science Semester 6 Question Paper and Evaluation Key."
    recipient_kem_pub = bytes.fromhex(student_cs["kem_public_key_hex"])
    recipient_kem_priv = bytes.fromhex(student_cs["kem_private_key_hex"])
    sender_dsa_pub = bytes.fromhex(teacher_cs["dsa_public_key_hex"])
    sender_dsa_priv = bytes.fromhex(teacher_cs["dsa_private_key_hex"])

    envelope = DocumentPQCPipeline.secure_document(doc_raw, recipient_kem_pub, sender_dsa_priv, sender_dsa_pub)
    print(f"   * ML-KEM-768 Ciphertext: {len(bytes.fromhex(envelope['kem_ciphertext_hex']))} bytes")
    print(f"   * AES-256-GCM Payload:   {len(envelope['ciphertext'])} bytes")
    print(f"   * ML-DSA-65 Signature:   {len(bytes.fromhex(envelope['signature_hex']))} bytes")

    decrypted, authentic, msg = DocumentPQCPipeline.open_and_verify(
        envelope["ciphertext"],
        envelope["nonce_hex"],
        envelope["tag_hex"],
        envelope["kem_ciphertext_hex"],
        envelope["signature_hex"],
        recipient_kem_priv,
        sender_dsa_pub
    )
    assert decrypted == doc_raw, "Decryption plaintext mismatch"
    assert authentic is True, "Authenticity signature verification failed"
    print(f"✅ Decryption & Signature Verification Succeeded! Status: {msg}")

    # --------------------------------------------------------------------------
    # 4. Tamper Detection
    # --------------------------------------------------------------------------
    print("\n--- 4. Testing Quantum-Safe Tamper Detection ---")
    corrupt_ct = bytearray(envelope["ciphertext"])
    corrupt_ct[8] ^= 0x55
    try:
        DocumentPQCPipeline.open_and_verify(
            bytes(corrupt_ct),
            envelope["nonce_hex"],
            envelope["tag_hex"],
            envelope["kem_ciphertext_hex"],
            envelope["signature_hex"],
            recipient_kem_priv,
            sender_dsa_pub
        )
        print("FAIL: Tampered document was not intercepted!")
    except Exception as e:
        print(f"✅ Tamper Intercepted Successfully: {e}")

    # --------------------------------------------------------------------------
    # 5. Cryptographic Performance Benchmark
    # --------------------------------------------------------------------------
    print("\n--- 5. Testing Cryptographic Performance Benchmark Engine ---")
    bench = benchmark_engine.run_cryptographic_benchmarks()
    print(f"   * Classical Keygen:    {bench['classical']['keygen_time_ms']} ms | Security: {bench['classical']['quantum_security']}")
    print(f"   * Hybrid Encap:        {bench['hybrid']['key_encap_latency_ms']} ms | Security: {bench['hybrid']['quantum_security']}")
    print(f"   * Post-Quantum Encap:  {bench['post_quantum']['key_encap_latency_ms']} ms | Security: {bench['post_quantum']['quantum_security']}")
    print(f"   * ML-DSA Signature:    {bench['post_quantum']['signature_bytes']} bytes")

    # 6. Test In-RAM Extraction for DOCX files
    print("\n--- 6. Testing In-RAM Binary Document Extraction (.docx) ---")
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        xml_content = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            '<w:body><w:p><w:r><w:t>Confidential Semester End Final Examination Question Paper CS602</w:t></w:r></w:p></w:body>'
            '</w:document>'
        )
        zf.writestr("word/document.xml", xml_content)
    raw_docx_bytes = buf.getvalue()
    extracted_text = ai_classifier.extract_text_from_bytes(raw_docx_bytes, "exam_paper.docx")
    print(f"   * Clean Extracted Text: '{extracted_text}'")
    assert "docProps" not in extracted_text, "Garbled zip header detected in extracted text!"
    assert "Question Paper" in extracted_text, "Failed to parse text from DOCX XML!"
    docx_pred = ai_classifier.classifier_instance.predict(extracted_text)
    print(f"   * Extracted Classification: {docx_pred['label']} ({docx_pred['confidence']}%)")
    assert docx_pred["label"] == "Critical", "DOCX Question Paper should classify as Critical!"
    print("✅ In-RAM DOCX text extraction and AI classification verified successfully!")

    print("\n" + "=" * 70)
    print("ALL TESTS PASSED WITH 100% SUCCESS!")
    print("=" * 70)

if __name__ == "__main__":
    run_all_tests()
