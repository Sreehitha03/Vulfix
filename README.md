## VulfixAI: Automated Vulnerability Remediation with LLMs
VulfixAI streamlines vulnerability management by integrating scanners (like Trivy) with LLMs to analyze, categorize, and automatically propose fixes via GitHub Pull Requests—accelerating your security workflow.

## Features
1. Scanner Integration: Ingests reports from tools like Trivy.
2. LLM-Powered Analysis: Uses Gemma 3:1b via Ollama to classify vulnerabilities as True Positive, False Positive, or Uncertain.
3. Fix Suggestions: Recommends specific remediations (e.g., version upgrades).
4. Automated PRs: Applies fixes, pushes changes, and creates Pull Requests on GitHub.

## Requirements
1. Python
2. Trivy (can be downloaded from github)
3. Ollama (to run Gemma 3:1b/ any model locally)
4. GitHub Personal Access Token with repo scope

## Usage 
1. Run Scan + LLM Analysis
```   
python vulfix.py giturl \
--type repo \
--output reports/outputfilename.json \
--summary-output reports/pr_summary.md \
--actionable-fixes-output reports/actionable_fixes.json
```
Clones the repo, scans it, and generates LLM-processed reports.

2. Start Local LLM
```
ollama run gemma3:1b
```

3. Create Automated PR
```
python autopr.py \
--repo-url giturl \
--actionable-fixes reports/actionable_fixes.json
```
Applies fixes, creates a branch, and opens a Pull Request.

4. if you want to scan only the current file you are working on
```
python vulfix.py path/to/your/file.js \
--type file \
--output reports/your_file.json 
```

## ⚠️ Notes
1. Ensure npm is in PATH or manually specify in autopr.py if needed.
2. Code patch automation is limited; package_upgrade is currently supported.
