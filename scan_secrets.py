#!/usr/bin/env python3
"""
Script simple pour tester la détection de secrets
Démontre comment les outils de sécurité trouvent les credentials en clair
"""

import re
import json
from pathlib import Path

# Patterns simples pour détecter les secrets courants
PATTERNS = {
    "password": r"password\s*[:=]\s*['\"]?([^\s'\"]+)['\"]?",
    "api_key": r"(api[_-]?key|apikey)\s*[:=]\s*['\"]?([a-zA-Z0-9\-_]{20,})['\"]?",
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "aws_secret": r"(['\"])[a-zA-Z0-9/+=]{40}(['\"])",
    "mongodb_uri": r"mongodb\+?srv?://[^:]+:[^@]+@",
    "private_key": r"-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----",
}

def scan_file(filepath):
    """Scanner un fichier à la recherche de secrets"""
    try:
        with open(filepath, 'r') as f:
            content = f.read()
    except:
        return []
    
    findings = []
    for secret_type, pattern in PATTERNS.items():
        for match in re.finditer(pattern, content, re.IGNORECASE):
            line_num = content[:match.start()].count('\n') + 1
            findings.append({
                "type": secret_type,
                "file": str(filepath),
                "line": line_num,
                "match": match.group(0)[:50] + "..." if len(match.group(0)) > 50 else match.group(0)
            })
    return findings

def main():
    """Scan le dossier test_secrets"""
    test_dir = Path("test_secrets")
    
    if not test_dir.exists():
        print("❌ Dossier test_secrets non trouvé!")
        return
    
    print("🔍 Scan du dossier test_secrets...\n")
    print("=" * 70)
    
    all_findings = []
    for file in test_dir.rglob("*"):
        if file.is_file() and (file.suffix in ['.js', '.py', '.env', '.txt', '.config']):
            findings = scan_file(file)
            all_findings.extend(findings)
    
    if all_findings:
        print(f"\n⚠️  {len(all_findings)} SECRETS TROUVÉS!\n")
        for finding in all_findings:
            print(f"  📄 Fichier: {finding['file']}")
            print(f"  🔑 Type: {finding['type']}")
            print(f"  📍 Ligne: {finding['line']}")
            print(f"  📋 Contenu: {finding['match']}")
            print("  " + "-" * 66)
        
        # Export JSON
        with open("scan_results.json", "w") as f:
            json.dump(all_findings, f, indent=2)
        print(f"\n✅ Résultats exportés dans scan_results.json")
    else:
        print("\n✅ Aucun secret détecté")

if __name__ == "__main__":
    main()
