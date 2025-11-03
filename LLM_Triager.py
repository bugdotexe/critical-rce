#!/usr/bin/env python3

"""
Contextual LLM Decision Maker for Dependency Confusion (using OpenAI) - v10.2

This standalone script delegates all decision-making to the LLM.
It does not "teach" the LLM rules, it treats the LLM as an expert.

1.  It automatically detects and uses 'ripgrep' (rg) for fast context search.
2.  It uses the '-F' (fixed-strings) flag for accurate, fast searches.
3.  It strips ANSI color codes from input files.
4.  It finds *all* context for *every* package.
5.  It passes the evidence to a new, simplified "Expert Analyst" prompt.
6.  The LLM uses its own vast, built-in knowledge to make a final,
    expert determination.

Usage:
    python3 LLM_Triager.py /path/to/my/project
    (e.g., python3 LLM_Triager.py /tmp/elastic)
"""

import os
import sys
import json
import time
import requests # You may need to install this: pip install requests
import csv
import subprocess
import re
import shutil
from typing import List, Dict, Optional, Any

# --- Configuration ---

API_KEY = os.environ.get("OPENAI_API_KEY")
API_URL = "https://api.openai.com/v1/chat/completions"
MODEL_NAME = "gpt-4o"
SEARCH_TIMEOUT = 15 # Timeout for each rg/grep command

# ANSI color codes for summary
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    RED = '\033[1;31m'
    GREEN = '\033[1;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[1;34m'
    WHITE = '\033[1;37m'
    GREY = '\033[0;37m'

# This will be set to True if 'rg' is found
USE_RIPGREP = False

# --- V10 "EXPERT ANALYST" SYSTEM PROMPT ---
# This prompt provides a role and a task, not a list of rules.
# It trusts the LLM to be the expert.
SYSTEM_PROMPT = """
You are a principal cybersecurity analyst at a top-tier security firm. Your sole focus is on supply chain security, specifically dependency confusion and repository takeovers.

You are given a case file for a single package. This package is *already confirmed* to be available for registration on a public registry (like npm, PyPI, etc.).

Your case file contains:
1.  `package_name`: The name of the available package.
2.  `package_type`: The ecosystem (e.g., "npm", "pip", "github").
3.  `home_org`: The name of the client organization we are auditing (e.g., "elastic").
4.  `context_snippets`: A list of code snippets from the client's codebase where this package name was found.

**Your Task:**
Analyze all the evidence. Use your expert knowledge to decide if this is a **Potential Vulnerability** or a **False Positive**.

-   **A "Potential Vulnerability" is:**
    -   Classic dependency confusion (e.g., a package like `elastic-internal-tool` or `@elastic/auth` used without a private source).
    -   Scope takeover (e.g., a generic, unregistered scope like `@my-scope/package`).
    -   Repo takeover (e.g., a `github` type package pointing to a deleted user).

-   **A "False Positive" is:**
    -   A public, third-party package (e.g., `@babel/parser`, `sphinx_rtd_theme`).
    -   A package explicitly sourced from elsewhere (e.g., context shows `"dependency": "github:..."` or `"workspace:..."`).
    -   A random string that happens to match the name.

**Response Format:**
Deliver your final analysis as a *single JSON object* and nothing else.
{
  "package_name": "string",
  "classification": "string (must be 'Potential Vulnerability' or 'False Positive')",
  "justification": "string (Your concise, expert justification for your decision. 1-2 sentences.)",
  "highest_risk_context": "string (The single best line of evidence. If no good evidence, write 'N/A'.)"
}
"""

# --- Functions ---

def check_for_ripgrep() -> bool:
    """Checks if 'rg' (ripgrep) is in the system PATH."""
    if shutil.which("rg"):
        print(f"[{Colors.GREEN}INFO{Colors.RESET}] 'ripgrep' (rg) detected. Using for fast search.")
        return True
    else:
        print(f"[{Colors.YELLOW}WARN{Colors.RESET}] 'ripgrep' (rg) not found in PATH.")
        print(f"[{Colors.YELLOW}WARN{Colors.RESET}] Falling back to 'grep'. For large projects, this may be slow or time out.")
        print(f"[{Colors.YELLOW}WARN{Colors.RESET}] Recommend installing ripgrep for a massive speed improvement.")
        return False

def strip_ansi_codes(text: str) -> str:
    """Removes ANSI escape codes (like colors) from a string."""
    if not text:
        return ""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def run_search(pattern: str, search_dir: str, line_numbers: bool, case_insensitive: bool, fixed_string: bool) -> str:
    """
    Helper to run 'rg' or 'grep' and return stdout.
    'rg' is the preferred, much faster tool.
    """
    global USE_RIPGREP
    
    flags = ""
    if line_numbers:
        flags += "n"
    if case_insensitive:
        flags += "i"

    # Use -F for fixed_string search, -E for regex search
    search_mode_flag = "F" if fixed_string else "E"

    if USE_RIPGREP:
        # Use ripgrep
        # We must use subprocess.list2cmdline to handle quotes in the pattern
        cmd_list = [
            "rg",
            f"-{flags}{search_mode_flag}",
            "--no-heading",
            "--no-ignore",
            "-g", "!llm_analysis_report.csv",
            "-g", "!.potential",
            pattern,
            search_dir
        ]
        command = subprocess.list2cmdline(cmd_list)
    else:
        # Use grep
        command = (
            f"grep -r{flags}{search_mode_flag} \"{pattern}\" \"{search_dir}\" "
            f"| grep -vE \"(llm_analysis_report.csv|\\.potential)\""
        )

    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=SEARCH_TIMEOUT)
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        print(f"    [{Colors.YELLOW}WARN{Colors.RESET}] Search command timed out (>{SEARCH_TIMEOUT}s): {command.split('|')[0]}...")
    except Exception as e:
        print(f"    [{Colors.RED}ERROR{Colors.RESET}] Search command failed: {e}")
    return ""

def find_all_context(package_name: str, search_dir: str) -> List[Dict[str, Any]]:
    """
    Uses 'rg' or 'grep' to find *all* occurrences of the package name.
    """
    contexts = []
    
    # This pattern is now a fixed string
    pattern = package_name
    
    # We call run_search with fixed_string=True
    search_stdout = run_search(
        pattern, 
        search_dir, 
        line_numbers=True, 
        case_insensitive=True, # 'rg -iF' works well
        fixed_string=True
    )
            
    if search_stdout:
        lines = search_stdout.strip().split('\n')
        for line in lines[:20]: # Limit to 20 lines of context
            if not line.strip():
                continue
            
            # --- Robust Parser ---
            # This regex splits the line into 'path', 'line_number', and 'content'
            # It handles file paths that may or may not contain colons.
            match = re.match(r'([^:]+):(\d+):(.*)', line)
            
            if match:
                file_path, line_num_str, content = match.groups()
                line_num = int(line_num_str)
                content = content.strip()
                
                if len(content) > 300: # Truncate long lines
                    content = content[:300] + "..."
                    
                contexts.append({
                    "file": os.path.relpath(file_path, search_dir), # Use relative path
                    "line": line_num,
                    "content": content
                })
            else:
                # This handles the intermittent parsing warning
                print(f"    [{Colors.YELLOW}WARN{Colors.RESET}] Could not parse search output line: {line[:70]}...")
    
    if not contexts:
        print(f"    [{Colors.BLUE}INFO{Colors.RESET}] No context found for '{package_name}'. Analyzing name only.")
        
    return contexts

def analyze_with_llm(package_name: str, package_type: str, home_org: str, context_list: List[Dict[str, Any]], max_retries: int = 3) -> Optional[Dict[str, Any]]:
    """
    Calls the OpenAI API to analyze the package.
    """
    print(f"  [{Colors.BLUE}LLM{Colors.RESET}] Analyzing {package_type} package: {Colors.BOLD}{package_name}{Colors.RESET} (with {len(context_list)} context snippets)")

    if context_list:
        context_str = json.dumps(context_list, indent=2)
    else:
        context_str = "No source code context was found. Analyze based on the package name and type alone."

    user_query = f"""
    "package_name": {json.dumps(package_name)},
    "package_type": {json.dumps(package_type)},
    "home_org": {json.dumps(home_org)},
    "context_snippets":
    {context_str}

    Deliver your final analysis as a single JSON object.
    """

    payload = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_query}
        ],
        "response_format": {"type": "json_object"}
    }

    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {API_KEY}'
    }

    for attempt in range(max_retries):
        try:
            response = requests.post(API_URL, headers=headers, data=json.dumps(payload), timeout=60)
            if response.status_code == 200:
                result = response.json()
                json_text = result.get('choices', [{}])[0].get('message', {}).get('content', '{}')
                analysis = json.loads(json_text)
                analysis['package_type'] = package_type
                return analysis
            else:
                print(f"    [{Colors.YELLOW}WARN{Colors.RESET}] API request failed with status {response.status_code}: {response.text}")
                if 400 <= response.status_code < 500: return None
        except requests.RequestException as e:
            print(f"    [{Colors.YELLOW}WARN{Colors.RESET}] API request exception: {e}")
        
        wait = (2 ** attempt)
        print(f"    [{Colors.BLUE}INFO{Colors.RESET}] Retrying in {wait}s...")
        time.sleep(wait)

    print(f"    [{Colors.RED}ERROR{Colors.RESET}] Failed to analyze package '{package_name}' after {max_retries} attempts.")
    return None

def print_summary(report_path: str):
    """
    Reads the generated CSV report and prints a formatted summary.
    """
    print(f"[{Colors.BLUE}INFO{Colors.RESET}] Analysis complete. Full report at: {report_path}")
    
    try:
        with open(report_path, 'r') as f:
            reader = csv.DictReader(f)
            results = list(reader)
        
        if not results:
            print(f"[{Colors.YELLOW}WARN{Colors.RESET}] LLM analysis ran but the report is empty. No packages to summarize.")
            return

        potential_vulns = [r for r in results if r['classification'] == 'Potential Vulnerability']
        false_positives = [r for r in results if r['classification'] == 'False Positive']
        failed_analysis = [r for r in results if r['classification'] == 'Analysis Failed']

        print(f"{Colors.BLUE}---------------------------------{Colors.RESET}")
        print(f"  {Colors.BOLD}LLM Triage Summary{Colors.RESET}")
        print(f"{Colors.BLUE}---------------------------------{Colors.RESET}")
        print(f"  Total Packages Analyzed: {Colors.BOLD}{len(results)}{Colors.RESET}")
        print(f"  {Colors.YELLOW}Potential Vulnerabilities: {len(potential_vulns)}{Colors.RESET}")
        print(f"  {Colors.GREEN}False Positives: {len(false_positives)}{Colors.RESET}")
        print(f"  {Colors.RED}Failed to Analyze: {len(failed_analysis)}{Colors.RESET}")
        print(f"{Colors.BLUE}---------------------------------{Colors.RESET}")

        if potential_vulns:
            print(f"[{Colors.YELLOW}!!{Colors.RESET}] {Colors.YELLOW}Potential Vulnerabilities Found:{Colors.RESET}")
            for vuln in potential_vulns:
                print(f"    {Colors.YELLOW}[VULN]{Colors.RESET} {Colors.BOLD}{vuln['package_name']}{Colors.RESET} ({vuln['package_type']})")
                print(f"           {Colors.GREY}Justification: {vuln['justification']}{Colors.RESET}")
                print(f"           {Colors.GREY}Highest Risk: {vuln['highest_risk_context']}{Colors.RESET}\n")
        else:
            print(f"  {Colors.GREEN}[INFO]{Colors.RESET} No potential vulnerabilities identified.")
        
        print(f"{Colors.BLUE}---------------------------------{Colors.RESET}")

    except FileNotFoundError:
        print(f"[{Colors.RED}ERROR{Colors.RESET}] LLM analysis ran but no report file was found at {report_path}.")
    except Exception as e:
        print(f"[{Colors.RED}ERROR{Colors.RESET}] Failed to read or parse summary from {report_path}: {e}")

def main(source_dir: str, target_org: str):
    """
    Main function: find files, gather evidence, send to LLM, print summary.
    """
    global USE_RIPGREP
    USE_RIPGREP = check_for_ripgrep() # Check for 'rg' at the start

    if not API_KEY:
        print(f"[{Colors.RED}ERROR{Colors.RESET}] 'OPENAI_API_KEY' environment variable not set. Aborting LLM analysis.", file=sys.stderr)
        sys.exit(1)

    print(f"[{Colors.BLUE}INFO{Colors.RESET}] Starting Contextual LLM analysis for source directory: {source_dir}")
    print(f"[{Colors.BLUE}INFO{Colors.RESET}] Using '{Colors.BOLD}{target_org}{Colors.RESET}' as the home organization name.")
    
    dep_dir = os.path.join(source_dir, "DEP")
    results = []
    
    try:
        potential_files = [f for f in os.listdir(dep_dir) if f.endswith(".potential")]
    except FileNotFoundError:
        print(f"[{Colors.RED}ERROR{Colors.RESET}] Dependency directory not found: {dep_dir}", file=sys.stderr)
        sys.exit(1)

    if not potential_files:
        print(f"[{Colors.BLUE}INFO{Colors.RESET}] No '.potential' files found in {dep_dir}. Nothing to analyze.")
        sys.exit(0)

    print(f"[{Colors.BLUE}INFO{Colors.RESET}] Found potential files to scan: {Colors.BOLD}{', '.join(potential_files)}{Colors.RESET}")

    for filename in potential_files:
        file_path = os.path.join(dep_dir, filename)
        base_name = filename.replace(".potential", "")
        package_type = base_name.split('-')[-1] 
        if not package_type: package_type = "unknown"

        print(f"[{Colors.BLUE}INFO{Colors.RESET}] Processing {package_type} packages from {filename}...")
        try:
            # --- THIS IS THE FIX ---
            with open(file_path, 'r') as f:
                content = f.read()
            
            package_names = [strip_ansi_codes(line.strip()) for line in content.splitlines() if line.strip()]
            # --- END FIX ---
            
            if not package_names:
                print(f"[{Colors.BLUE}INFO{Colors.RESET}] File {filename} is empty.")
                continue

            for package_name in package_names:
                
                # --- STEP 1: Gather Evidence ---
                context_snippets = find_all_context(package_name, source_dir)
                
                # --- STEP 2: Send to LLM for Decision ---
                analysis = analyze_with_llm(package_name, package_type, target_org, context_snippets)
                
                if analysis:
                    results.append(analysis)
                else:
                    results.append({
                        "package_name": package_name,
                        "package_type": package_type,
                        "classification": "Analysis Failed",
                        "justification": "API call failed after retries.",
                        "highest_risk_context": "N/A"
                    })
                time.sleep(1) # Rate limit

        except Exception as e:
            print(f"[{Colors.RED}ERROR{Colors.RESET}] Failed to read or process file {file_path}: {e}", file=sys.stderr)

    # --- Write CSV Report ---
    report_path = os.path.join(source_dir, "llm_analysis_report.csv")
    if results:
        print(f"[{Colors.BLUE}INFO{Colors.RESET}] Writing LLM analysis report to: {report_path}")
        try:
            with open(report_path, 'w', newline='') as csvfile:
                fieldnames = ['package_name', 'package_type', 'classification', 'justification', 'highest_risk_context']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                writer.writeheader()
                for row in results:
                    filtered_row = {k: v for k, v in row.items() if k in fieldnames}
                    writer.writerow(filtered_row)
        except Exception as e:
            print(f"[{Colors.RED}ERROR{Colors.RESET}] Failed to write report {report_path}: {e}", file=sys.stderr)
    else:
        print(f"[{Colors.BLUE}INFO{Colors.RESET}] No packages were analyzed. No report generated.")

    print(f"[{Colors.BLUE}INFO{Colors.RESET}] Contextual LLM analysis task finished.")
    
    # --- Print Summary ---
    print_summary(report_path)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <source_directory>", file=sys.stderr)
        print(f"Example: python3 {sys.argv[0]} /tmp/my-target-org", file=sys.stderr)
        sys.exit(1)
        
    source_directory = sys.argv[1]
    target_organization = os.path.basename(source_directory.rstrip(os.sep))
    
    if not os.path.isdir(source_directory):
        print(f"[{Colors.RED}ERROR{Colors.RESET}] Source directory not found: {source_directory}", file=sys.stderr)
        sys.exit(1)

    main(source_directory, target_organization)

