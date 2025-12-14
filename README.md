# AI-Powered Nuclei Template Recommendation Tool for Application Security & Vulnerability Assessment

This project is an **experimental security automation tool** that helps in **selecting relevant Nuclei templates** for a target based on its **technology stack**.

The main goal of this tool is **not to run Nuclei**, but to **recommend which templates you should run** for better focus and time saving during security testing or bug bounty work.

This project is still **under active improvement**, especially around **accuracy**, but the **overall flow and process are working correctly**.

# Why I Built This

When using Nuclei, there are **10,000+ templates**, and running all of them is:

* Very slow
* Noisy
* Often unnecessary

I wanted a way to:

* Analyze a target
* Understand its tech stack
* Automatically suggest **only the most relevant templates**
* Use **AI reasoning**, not just keyword matching

This tool is my attempt to solve that problem.

##  What This Tool Does

1. Takes a **domain** as input
2. Uses recon tools (httpx, wafw00f, headers, etc.)
3. Extracts a **clean tech stack** (WAF, CMS, JS libs, headers, versions)
4. Filters 10k+ Nuclei templates using **logic-based filtering**
5. Sends shortlisted templates to **local AI models (Ollama)**
6. AI recommends the **most relevant templates**
7. Outputs **final template paths only**

You run Nuclei yourself later with those templates.

## Technologies Used

* **Python 3**
* **Nuclei templates**
* **Ollama (local AI)**

  * `phi3:mini`
  * `qwen2.5-coder`
* **httpx**
* **wafw00f**
* **shcheck**
* Regex-based parsing
* AI prompt engineering

Everything runs **locally**, no paid APIs.

---

## Installation

###  Clone the repo

```bash
git clone https://github.com/ashhadali10/Nuclei_template_recommendation.git
cd Nuclei_template_recommendation
```

### Requirements

Make sure these tools are installed:

* Python 3
* httpx
* wafw00f
* nuclei templates
* Ollama

Pull AI models:

```bash
ollama pull phi3:mini
ollama pull qwen2.5-coder
```

---

## How to Run

```bash
python3 Ai_template_Recomm.py -d domain.com
```

### Example Output

```
Target: domain.com
[+] Clean Tech Stack: cloudflare, cms, csp, hsts, hubspot, jquery
[+] Total Templates: 11753
[+] Templates after logic filter: 260
[+] AI Candidates: 83

FINAL RECOMMENDATIONS:
- ./http/misconfiguration/weak-csp-detect.yaml
- ./dast/vulnerabilities/xss/csp-bypass/cloudflare-challenges-csp-bypass.yaml
- ./dast/vulnerabilities/xss/csp-bypass/googleapis-blogger-csp-bypass.yaml
...
```


## Output Files

For each target, results are saved in:

```
output/<domain>/vulns/
```

Important files:

* `complete_Techstack.txt` → Clean extracted tech stack
* `ai_recommended_templates.txt` → Final recommended templates

However:

* The **process**
* The **flow**
* The **automation logic**
  are working correctly and consistently.

This project is focused on **learning, experimentation, and improvement**.


## What I Am Actively Improving

* Better tech stack extraction (languages, frameworks, versions)
* Smarter stop-word filtering
* Template severity awareness
* Confidence scoring for recommendations
* Reduced false positives
* Better AI prompts



##  Future Ideas

* Auto-group templates by category (CVE, misconfig, exposure)
* WAF-aware template selection
* SSL/TLS-specific template suggestions
* Explain **why** a template was selected
* Streaming mode for large targets


## About Me

I am actively learning and building tools in:

* Application Security
* Bug Bounty Automation
* DevSecOps
* AI-assisted security workflows


## Final Note

This is **not a finished product**.
This is a **working prototype with real logic**, built to learn and improve.

Feedback, ideas, and improvements are always welcome.
