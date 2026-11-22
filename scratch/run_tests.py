import subprocess, sys, os, json, pathlib, traceback

project_dir = r'C:/Users/Thanushree/AI-Based-Post-Quantum-Secure-Document-Sharing-and-Verification_System'
# Actually the path has spaces? The folder name includes hyphens not spaces. Use correct path.
project_dir = r'C:/Users/Thanushree/AI-Based-Post-Quantum-Secure-Document-Sharing-and-Verification-System'

# run unittest
result = subprocess.run([sys.executable, '-m', 'unittest', 'test_system.py'], cwd=project_dir, capture_output=True, text=True)
print('--- STDOUT ---')
print(result.stdout)
print('--- STDERR ---')
print(result.stderr)
print('--- RETURN CODE ---', result.returncode)
