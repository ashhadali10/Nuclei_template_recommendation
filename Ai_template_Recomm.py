#!/usr/bin/env python3
"""
AI-Powered Nuclei Template Recommender v7 (Polished)
Author: Ashhad Ali
Usage: python3 Ai_template_Recomm.py -d relocity.com

Requirements:
  - ollama pull phi3:mini
  - ollama pull qwen2.5-coder
"""

import re
import json
import argparse
import subprocess
import sys
from pathlib import Path

# ================= CONFIG =================
BASE_DIR = Path("/home/ashhad/bugbounty/automation_script/output")
TEMPLATE_JSON = Path("/home/ashhad/bugbounty/automation_script/templates_index.json")

MODELS = ["phi3:mini", "qwen2.5-coder"]

CHUNK_SIZE = 15
FINAL_PICK = 10
AI_TIMEOUT = 200
MAX_TEMPLATES = 300
# =========================================


# ---------------- CORE HELPERS ----------------

def run_cmd(cmd, output_file=None, timeout=120):
    """Executes shell commands with timeout handling."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        if output_file:
            output_file.write_text(result.stdout + result.stderr)
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        if output_file:
            output_file.write_text(f"[!] Command timed out after {timeout}s\n")
        return ""
    except Exception:
        return ""


def is_valid_tech_token(token: str, domain_name: str) -> bool:
    """Filters out garbage, symbols, and the domain name itself."""
    token = token.strip().lower()

    # Must contain at least one letter
    if not re.search(r"[a-z]", token):
        return False

    # Reject short random strings (optional, keep > 2 chars)
    if len(token) < 3:
        return False

    # Reject pure symbols
    if re.fullmatch(r"[\*\+\-_~\.]+", token):
        return False

    # Reject if token IS the domain name (e.g., 'relocity' in relocity.com)
    if token == domain_name:
        return False

    # Blacklist junk words
    blacklist = {
        "*", "+", "~", "-",
        "www", "httpx", "http", "https",
        "projectdiscovery", "io", "com", "net", "org",
        "domain", "url", "dns", "s3", "bucket"
    }

    if token in blacklist:
        return False

    return True


# ---------------- TECH EXTRACTION ----------------

def extract_tech(vulns_dir, domain):
    """Parses tool outputs to create a clean list of technologies."""
    tech = set()
    
    # Extract clean domain name (e.g., relocity.com -> relocity)
    domain_clean = domain.split('.')[0].lower()

    # ---------- HTTPX ----------
    httpx_file = vulns_dir / "httpx_tech.txt"
    if httpx_file.exists():
        content = re.sub(r"\x1B\[[0-9;]*[mK]", "", httpx_file.read_text())

        # Regex to find words (letters/numbers/dots/dashes)
        candidates = re.findall(r"\b[a-zA-Z][a-zA-Z0-9\-\.]{2,}\b", content)

        stopwords = {
            "the", "use", "current", "management", "version", "latest",
            "enabled", "disabled", "mobile", "option", "public",
            "dashboard", "login", "application", "server", "client", 
            "detect", "technology", "cookieyes", "hub", "zurb", "wrn"
        }

        for c in candidates:
            c = c.lower().strip()
            
            # Skip stopwords, IPs, and invalid tokens
            if c in stopwords:
                continue
            if c.startswith(("10.", "127.", "192.", "199.")):
                continue
            
            if is_valid_tech_token(c, domain_clean):
                tech.add(c)

    # ---------- SECURITY HEADERS ----------
    headers_file = vulns_dir / "security_headers.txt"
    if headers_file.exists():
        content = headers_file.read_text().lower()
        header_map = {
            "strict-transport-security": "hsts",
            "content-security-policy": "csp",
            "x-frame-options": "x-frame-options"
        }
        for header, key in header_map.items():
            if header in content:
                tech.add(key)

    # ---------- WAF ----------
    waf_file = vulns_dir / "waf.txt"
    if waf_file.exists():
        content = re.sub(r"\x1B\[[0-9;]*[mK]", "", waf_file.read_text())
        wafs = re.findall(r"\[([^\]]+)\]", content)
        for w in wafs:
            w = w.lower().strip()
            if is_valid_tech_token(w, domain_clean):
                tech.add(w)

    # Final cleanup and sort
    sorted_tech = sorted(list(tech))
    
    tech_file = vulns_dir / "complete_Techstack.txt"
    tech_file.write_text("\n".join(sorted_tech))
    tech_blob = ", ".join(sorted_tech)

    return tech_file, tech_blob


# ---------------- LOGIC FILTER ----------------

def logic_filter(templates, tech_blob):
    """Pre-filters templates using EXACT matching (not partial)."""
    shortlisted = []

    # Create a list of valid tech tokens
    tech_list = [t.strip().lower() for t in tech_blob.split(",") if t.strip()]
    
    print(f"[*] Logic Filtering Keywords: {tech_list}")

    for t in templates:
        if len(shortlisted) >= MAX_TEMPLATES:
            break

        # ID of the template (e.g., wordpress-login)
        t_id = t.get("id", "").lower()
        # Keywords in the template
        keywords = [k.lower() for k in t.get("keywords", [])]

        # 1. Check ID against Tech List (Substring ok here: 'wordpress' fits 'wordpress-login')
        if any(tech in t_id for tech in tech_list):
            shortlisted.append(t)
            continue

        # 2. Check Keywords against Tech List (EXACT MATCH ONLY)
        # Prevents "in" matching "nginx" or "java" matching "javascript"
        if any(k in tech_list for k in keywords):
            shortlisted.append(t)

    return shortlisted


# ---------------- AI RANKING ----------------

def ai_rank_chunk(chunk, tech_blob, model):
    """Sends a batch of templates to AI for ranking."""
    entries = []
    
    # Format data for AI context: "Path | Tags"
    for t in chunk:
        kws = ", ".join(t.get("keywords", [])[:5])
        entries.append(f"Path: {t['path']} | Tags: {kws}")

    valid_paths = [t["path"] for t in chunk]
    clean_tech = re.sub(r"[^a-zA-Z0-9, \-_]", "", tech_blob)

    prompt = (
        f"Role: Senior Penetration Tester\n"
        f"Target Technologies: {clean_tech}\n\n"
        f"Candidate Templates:\n{chr(10).join(entries)}\n\n"
        f"Task: Select the 5 most relevant templates for this tech stack.\n"
        f"Output: ONLY raw file paths. No explanation."
    )

    try:
        result = subprocess.run(
            ["ollama", "run", model],
            input=prompt,
            text=True,
            capture_output=True,
            timeout=AI_TIMEOUT
        )
        
        # Parse output
        selected = []
        for line in result.stdout.splitlines():
            line = line.strip()
            # Fuzzy match: Is a valid path present in the AI's output line?
            for path in valid_paths:
                if path in line:
                    selected.append(path)
                    break # Stop checking other paths for this line
        
        return list(set(selected))

    except Exception as e:
        # print(f"[!] Error in chunk: {e}") # Uncomment for debug
        return []


def final_ai_select(candidates, tech_blob, model):
    """Final pass to pick the top 10."""
    if not candidates:
        return []

    clean_tech = re.sub(r"[^a-zA-Z0-9, \-_]", "", tech_blob)

    prompt = (
        f"Target Tech Stack: {clean_tech}\n\n"
        f"Templates:\n{chr(10).join(candidates)}\n\n"
        f"Task: Select Top {FINAL_PICK} highest impact templates.\n"
        f"Output: ONLY file paths."
    )

    try:
        result = subprocess.run(
            ["ollama", "run", model],
            input=prompt,
            text=True,
            capture_output=True,
            timeout=AI_TIMEOUT
        )
        
        final = []
        for line in result.stdout.splitlines():
            line = line.strip()
            for c in candidates:
                if c in line:
                    final.append(c)
        
        return list(dict.fromkeys(final))[:FINAL_PICK] # Remove dupes preserve order

    except Exception:
        return candidates[:FINAL_PICK]


# ---------------- MAIN ----------------

def main(domain):
    print(f"🎯 Target: {domain}")

    vulns_dir = BASE_DIR / domain / "vulns"
    vulns_dir.mkdir(parents=True, exist_ok=True)

    main_url = f"https://www.{domain}"

    # Basic Recon (Runs only if files missing)
    if not (vulns_dir / "httpx_tech.txt").exists():
        print("[*] Running recon tools...")
        run_cmd(f"httpx -u {main_url} -tech-detect -title -server", vulns_dir / "httpx_tech.txt")
        run_cmd(f"python3 /home/ashhad/bugbounty/shcheck/shcheck.py {main_url}", vulns_dir / "security_headers.txt")
        run_cmd(f"wafw00f {main_url}", vulns_dir / "waf.txt")
    else:
        print("[*] Recon files found, skipping active scan.")

    # Tech Extraction
    tech_file, tech_blob = extract_tech(vulns_dir, domain)
    print(f"[+] Clean Tech Stack: {tech_blob}")

    # Load Templates
    if not TEMPLATE_JSON.exists():
        print(f"[!] Error: Template index not found at {TEMPLATE_JSON}")
        sys.exit(1)

    try:
        templates = json.loads(TEMPLATE_JSON.read_text())
    except Exception as e:
        print(f"[!] Error reading JSON: {e}")
        sys.exit(1)

    print(f"[+] Total Templates: {len(templates)}")

    # Logic Filter
    filtered = logic_filter(templates, tech_blob)
    print(f"[+] Templates after logic filter: {len(filtered)}")

    if not filtered:
        print("[!] No matching templates found via logic filter.")
        sys.exit(0)

    # AI Processing
    combined = []
    total_chunks = (len(filtered) + CHUNK_SIZE - 1) // CHUNK_SIZE

    print(f"[+] Running AI Analysis ({len(MODELS)} models)...")
    
    for i in range(0, len(filtered), CHUNK_SIZE):
        chunk = filtered[i:i + CHUNK_SIZE]
        curr = (i // CHUNK_SIZE) + 1
        print(f"    > Chunk {curr}/{total_chunks}...", end="\r")
        
        for model in MODELS:
            matches = ai_rank_chunk(chunk, tech_blob, model)
            combined.extend(matches)
    print() # Newline

    candidates = list(set(combined))
    print(f"[+] AI Candidates: {len(candidates)}")

    # Final Selection
    final = final_ai_select(candidates, tech_blob, "qwen2.5-coder")

    # Output
    output = vulns_dir / "ai_recommended_templates.txt"
    output.write_text("\n".join(final))

    print("\n🏆 FINAL RECOMMENDATIONS:")
    for t in final:
        print(f"- {t}")


# ---------------- CLI ----------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domain", required=True)
    args = parser.parse_args()
    main(args.domain)
