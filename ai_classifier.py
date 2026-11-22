"""
AI Document Classifier: TF-IDF Vectorizer + Multi-Class Logistic Classifier
With robust in-RAM text extraction for DOCX, PDF, TXT, CSV, JSON, and Code.
Prevents binary corruption and extracts clean readable text.
"""

import re
import math
import io
import zlib
from typing import Dict, Any, List, Tuple

DOCUMENT_CORPUS = [
    # --- PUBLIC DOCUMENTS ---
    ("The college will remain closed on Friday on account of national holiday. All classes will resume on Monday.", "Public"),
    ("Academic Calendar for the academic year 2026-2027. Commencement of classes, mid-semester breaks, and final exam schedule.", "Public"),
    ("Department of Computer Science: Class timetable for Semester 6. Lecture halls, lab timings, and faculty allocations.", "Public"),
    ("Department of Electrical Engineering: Lecture timetable for Semester 4. Power electronics and control systems laboratory.", "Public"),
    ("Library Circular: Book borrowing rules, opening hours, and digital repository access for all students and faculty.", "Public"),
    ("Annual Sports Meet and Cultural Fest schedule. Registrations open for track events, debates, and musical performances.", "Public"),
    ("Syllabus and reference textbook recommendations for CS602: Cryptography and Network Security.", "Public"),
    ("Curriculum scheme and credit distribution for Bachelor of Technology degree programs.", "Public"),
    ("Bus route schedule and campus transportation timetable for the upcoming semester.", "Public"),
    ("Notice: Campus Wi-Fi configuration and registration guidelines for incoming students.", "Public"),
    ("Inviting registrations for National Hackathon and Coding Symposium. Open to all engineering students.", "Public"),
    ("Hostel Mess committee circular: Dining timings and weekly vegetarian and non-vegetarian food menu.", "Public"),

    # --- SENSITIVE DOCUMENTS ---
    ("Internal Assessment Test Marks: Department of Computer Science. Student roll numbers, marks scored in test 1 and test 2, and lab assignments.", "Sensitive"),
    ("Consolidated Continuous Assessment and Internal Evaluation Sheet: Electrical Engineering Semester 4. Microcontrollers and Circuit Theory.", "Sensitive"),
    ("Attendance shortfall roster: Students with attendance below 75 percent required to submit medical certificates and parent signatures.", "Sensitive"),
    ("Student Resume and Personal Curriculum Vitae: Phone number, residential address, previous GPA, and project details.", "Sensitive"),
    ("Scholarship application and annual family income certificate for fee concession under merit quota.", "Sensitive"),
    ("Consolidated Semester Grade Point Average (SGPA) and cumulative CGPA report for Batch 2023-2027.", "Sensitive"),
    ("Disciplinary committee report on student code of conduct violation during hostel inspections.", "Sensitive"),
    ("Student health clinic records and medical examination reports for sports team eligibility.", "Sensitive"),
    ("Student personal contact directory: Emergency guardian phone numbers, email addresses, and blood group data.", "Sensitive"),
    ("Provisional grade card and semester transcript with individual subject grade points.", "Sensitive"),

    # --- CRITICAL DOCUMENTS ---
    ("CONFIDENTIAL: End-Semester Examination Question Paper for CS604: Advanced Cryptography and Network Security. Total Marks 100. Time 3 Hours.", "Critical"),
    ("SECRET: Official Answer Key and Marking Scheme for Computer Science Semester 6 Final Exam.", "Critical"),
    ("Department of Electrical Engineering: End-Term Examination Question Paper for EE401: High Voltage Engineering. Strictly Confidential.", "Critical"),
    ("Official Solution Key and step-by-step marking rubrics for Electrical Machines Final Examination.", "Critical"),
    ("Office of the Controller of Examinations: Master question bank and moderated evaluation rubrics for upcoming university finals.", "Critical"),
    ("Campus Placement Drive: Shortlisted candidates, confidential salary packages, annual CTC offers, and signed employment contracts.", "Critical"),
    ("Strictly Confidential: Sealed question paper blueprint with section distributions for Midterm examination.", "Critical"),
    ("Master Answer Scheme and step-by-step solution key for Engineering Mathematics final examination.", "Critical"),
    ("Dean Examination Board: Moderation sheet for leaked or disputed question paper re-examination protocols.", "Critical"),
    ("External Examiner appointment letter and confidential evaluation stipend vouchers.", "Critical"),
]

STOP_WORDS = {
    "a", "about", "above", "after", "again", "against", "all", "am", "an", "and", "any", "are", "as", "at",
    "be", "because", "been", "before", "being", "below", "between", "both", "but", "by", "could", "did",
    "do", "does", "doing", "down", "during", "each", "few", "for", "from", "further", "had", "has", "have",
    "having", "he", "her", "here", "hers", "herself", "him", "himself", "his", "how", "i", "if", "in",
    "into", "is", "it", "its", "itself", "me", "more", "most", "my", "myself", "no", "nor", "not", "of",
    "off", "on", "once", "only", "or", "other", "our", "ours", "ourselves", "out", "over", "own", "same",
    "she", "should", "so", "some", "such", "than", "that", "the", "their", "theirs", "them", "themselves",
    "then", "there", "these", "they", "this", "those", "through", "to", "too", "under", "until", "up",
    "very", "was", "we", "were", "what", "when", "where", "which", "while", "who", "whom", "why", "with",
    "would", "you", "your", "yours", "yourself", "yourselves"
}

def tokenize(text: str) -> List[str]:
    clean_text = re.sub(r"[^a-zA-Z0-9\s]", " ", text.lower())
    tokens = clean_text.split()
    return [t for t in tokens if len(t) > 2 and t not in STOP_WORDS]


class TFIDFClassifier:
    def __init__(self):
        self.categories = ["Public", "Sensitive", "Critical"]
        self.vocabulary: Dict[str, int] = {}
        self.idf: Dict[str, float] = {}
        self.class_profiles: Dict[str, Dict[str, float]] = {c: {} for c in self.categories}
        self._fit()

    def _fit(self):
        doc_count = len(DOCUMENT_CORPUS)
        term_doc_freq = {}
        class_docs = {c: [] for c in self.categories}

        for text, category in DOCUMENT_CORPUS:
            class_docs[category].append(text)
            unique_terms = set(tokenize(text))
            for term in unique_terms:
                term_doc_freq[term] = term_doc_freq.get(term, 0) + 1

        for idx, (term, df) in enumerate(term_doc_freq.items()):
            self.vocabulary[term] = idx
            self.idf[term] = math.log((1 + doc_count) / (1 + df)) + 1.0

        for cat, texts in class_docs.items():
            cat_text = " ".join(texts)
            tokens = tokenize(cat_text)
            term_freqs = {}
            for t in tokens:
                term_freqs[t] = term_freqs.get(t, 0) + 1

            total_weight = 0.0
            weights = {}
            for t, tf in term_freqs.items():
                if t in self.idf:
                    w = (1 + math.log(tf)) * self.idf[t]
                    weights[t] = w
                    total_weight += w * w

            norm = math.sqrt(total_weight) if total_weight > 0 else 1.0
            self.class_profiles[cat] = {t: w / norm for t, w in weights.items()}

    def predict(self, raw_text: str) -> Dict[str, Any]:
        tokens = tokenize(raw_text)
        if not tokens:
            return {
                "label": "Public",
                "confidence": 60.0,
                "probabilities": {"Public": 60.0, "Sensitive": 20.0, "Critical": 20.0},
                "rationale": "Empty or unrecognized content; defaulted to lowest security tier.",
                "keywords": [],
                "recommended_department": "All Departments"
            }

        tf = {}
        for t in tokens:
            tf[t] = tf.get(t, 0) + 1

        doc_weights = {}
        total_sq = 0.0
        for t, count in tf.items():
            idf_val = self.idf.get(t, math.log(len(DOCUMENT_CORPUS) + 1))
            w = (1 + math.log(count)) * idf_val
            doc_weights[t] = w
            total_sq += w * w

        norm = math.sqrt(total_sq) if total_sq > 0 else 1.0
        doc_vector = {t: w / norm for t, w in doc_weights.items()}

        critical_signals = {"question", "paper", "exam", "examination", "confidential", "secret", "answer", "key", "marking", "ctc", "salary", "scheme", "rubric", "strictly", "moderation", "blueprint"}
        sensitive_signals = {"marks", "internal", "assessment", "attendance", "roster", "resume", "cv", "gpa", "cgpa", "sgpa", "income", "conduct", "grade", "provisional", "student", "roll", "shortfall"}
        public_signals = {"timetable", "calendar", "notice", "circular", "holiday", "library", "syllabus", "sports", "bus", "schedule", "registration", "guidelines", "general", "classes", "announcement"}

        scores = {}
        top_matches = {}
        for cat in self.categories:
            profile = self.class_profiles[cat]
            sim = sum(weight * profile.get(term, 0.0) for term, weight in doc_vector.items())
            matched_terms = [t for t in doc_vector if t in profile]
            top_matches[cat] = sorted(matched_terms, key=lambda t: doc_vector[t] * profile[t], reverse=True)[:5]
            scores[cat] = sim

        crit_count = sum(1 for t in tokens if t in critical_signals)
        sens_count = sum(1 for t in tokens if t in sensitive_signals)
        pub_count = sum(1 for t in tokens if t in public_signals)

        scores["Critical"] += 0.55 * crit_count
        scores["Sensitive"] += 0.40 * sens_count
        scores["Public"] += 0.25 * pub_count

        max_score = max(scores.values()) if scores else 0.0
        exp_scores = {c: math.exp(max(0.0, s - max_score + 1.0)) for c, s in scores.items()}
        sum_exp = sum(exp_scores.values())
        probs = {c: round((exp_scores[c] / sum_exp) * 100.0, 1) for c in self.categories}

        predicted_label = max(probs, key=probs.get)
        confidence = probs[predicted_label]

        keywords = top_matches.get(predicted_label, [])
        if not keywords:
            if predicted_label == "Critical":
                keywords = [t for t in tokens if t in critical_signals]
            elif predicted_label == "Sensitive":
                keywords = [t for t in tokens if t in sensitive_signals]
            else:
                keywords = [t for t in tokens if t in public_signals]

        cs_terms = {"computer", "science", "software", "algorithm", "cs602", "cs604", "cryptography", "network", "programming", "python", "data", "operating"}
        ee_terms = {"electrical", "electronics", "circuit", "circuits", "voltage", "power", "ee401", "machines", "signals", "microcontroller", "embedded"}

        cs_matches = sum(1 for t in tokens if t in cs_terms)
        ee_matches = sum(1 for t in tokens if t in ee_terms)

        if cs_matches > ee_matches and cs_matches >= 2:
            recommended_dept = "Computer Science"
        elif ee_matches > cs_matches and ee_matches >= 2:
            recommended_dept = "Electrical Engineering"
        else:
            recommended_dept = "All Departments"

        if predicted_label == "Critical":
            rationale = f"Detected examination and confidential evaluation keywords ({', '.join(keywords[:4]) or 'Confidential Material'}). Automatically assigned NIST Post-Quantum Protection."
        elif predicted_label == "Sensitive":
            rationale = f"Detected student performance & academic evaluation indicators ({', '.join(keywords[:4]) or 'Internal Assessment Records'}). Restricted to department students and faculty."
        else:
            rationale = f"Classified as general academic circular or institutional notice ({', '.join(keywords[:4]) or 'Public Notice'}). Cleared for broad institutional distribution."

        return {
            "label": predicted_label,
            "confidence": confidence,
            "probabilities": probs,
            "rationale": rationale,
            "keywords": keywords[:6],
            "recommended_department": recommended_dept
        }


def extract_text_from_bytes(file_bytes: bytes, filename: str) -> str:
    """
    Robust in-RAM text extraction for DOCX, PDF, TXT, CSV, JSON, Markdown, and code.
    Prevents binary replacement corruption (tH `@pS... docProps/core.xml).
    """
    if not file_bytes:
        return ""

    ext = filename.lower().split(".")[-1] if "." in filename else ""
    is_zip = file_bytes.startswith(b"PK\x03\x04")

    # 1. DOCX (Word Document) Parsing
    if ext in ["docx", "docm", "dotx"] or is_zip:
        try:
            import zipfile
            import xml.etree.ElementTree as ET
            with zipfile.ZipFile(io.BytesIO(file_bytes)) as z:
                extracted_parts = []
                for entry in z.namelist():
                    if entry.startswith("word/") and entry.endswith(".xml") and not entry.endswith("fontTable.xml") and not entry.endswith("styles.xml"):
                        xml_data = z.read(entry)
                        tree = ET.fromstring(xml_data)
                        part_nodes = []
                        for elem in tree.iter():
                            if elem.tag.endswith('}t') or elem.tag == 't':
                                if elem.text:
                                    part_nodes.append(elem.text)
                        if part_nodes:
                            extracted_parts.append(" ".join(part_nodes))
                if extracted_parts:
                    return "\n\n".join(extracted_parts).strip()
        except Exception:
            pass

    # 2. PDF Parsing
    if ext == "pdf":
        try:
            import pypdf
            reader = pypdf.PdfReader(io.BytesIO(file_bytes))
            pages = [p.extract_text() or "" for p in reader.pages]
            full_text = "\n".join(pages).strip()
            if full_text:
                return full_text
        except Exception:
            pass

        # Stream decompression fallback for PDF FlateDecode streams
        try:
            decompressed_chunks = []
            stream_blocks = re.findall(rb"stream[\r\n]+(.*?)[\r\n]+endstream", file_bytes, re.DOTALL)
            for block in stream_blocks:
                try:
                    decompressed = zlib.decompress(block)
                    text_matches = re.findall(r"\((.*?)\)\s*T[jJ]", decompressed.decode("latin-1", errors="ignore"))
                    if text_matches:
                        decompressed_chunks.extend(text_matches)
                except Exception:
                    continue
            if decompressed_chunks:
                return " ".join(decompressed_chunks).strip()
        except Exception:
            pass

    # 3. Plaintext formats (TXT, CSV, JSON, Markdown, Code)
    if ext in ["txt", "md", "csv", "json", "py", "java", "c", "cpp", "html", "xml", "log", ""]:
        try:
            return file_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return file_bytes.decode("latin-1", errors="ignore")

    # 4. Clean String Filter (Filter out non-printable binary bytes)
    try:
        raw_str = file_bytes.decode("latin-1", errors="ignore")
        # Extract readable English word tokens only
        tokens = re.findall(r"[A-Za-z0-9,.:;'\-\(\)\s]{4,}", raw_str)
        clean = " ".join([t.strip() for t in tokens if len(t.strip()) > 3 and not t.startswith("PK")])
        if clean:
            return clean[:4000]
    except Exception:
        pass

    return f"[File: {filename} ({len(file_bytes)} bytes)]"


classifier_instance = TFIDFClassifier()
