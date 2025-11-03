# --- v10.3 Enhanced "Expert Analyst" Prompt ---
SYSTEM_PROMPT = """
You are a principal cybersecurity analyst specializing in supply chain security.
You triage dependency confusion findings for large organizations.

Each package listed here is *confirmed to be publicly unregistered*.
Your job is to decide whether this represents a **Potential Vulnerability** or a **False Positive**.

Analyze the provided context carefully. The context contains real source code snippets and filenames where this dependency name appears.

Your reasoning should integrate these layers:
1. **Package semantics** – is the name brand-specific, internal, or generic?
2. **Ecosystem norms** – e.g., npm scopes (@org/package) vs. PyPI vs. GitHub.
3. **Contextual indicators** – e.g., mentions of "private", "internal", "local", "workspace", "git+https://", or company-specific paths.
4. **Likelihood of exposure** – whether the dependency looks like it’s used as a real dependency versus just a reference, test mock, or example.

Use your expertise and evidence to classify it.

Respond with strict JSON:

{
  "package_name": "string",
  "classification": "Potential Vulnerability" | "False Positive",
  "justification": "1-2 concise expert sentences justifying your decision.",
  "highest_risk_context": "Best single line of evidence, or 'N/A'.",
  "risk_signals": ["list of brief signals or indicators you noticed"]
}
"""

def analyze_with_llm(package_name: str, package_type: str, home_org: str, context_list: List[Dict[str, Any]], max_retries: int = 3) -> Optional[Dict[str, Any]]:
    """
    Calls the OpenAI API to analyze the package with enhanced signal extraction.
    """
    print(f"  [{Colors.BLUE}LLM{Colors.RESET}] Analyzing {package_type} package: {Colors.BOLD}{package_name}{Colors.RESET} (with {len(context_list)} context snippets)")

    # --- Context preprocessing / heuristic hints ---
    flags = []
    lname = package_name.lower()
    if lname.startswith('@') or '/' in lname:
        flags.append("scoped_or_namespaced_package")
    if any(k in lname for k in ["internal", "private", "conf", "corp", "secure", "intranet"]):
        flags.append("internal_naming_pattern")
    if lname.startswith(home_org.lower()) or lname.endswith(home_org.lower()):
        flags.append("organization_branded_name")

    evidence_lines = [c["content"] for c in context_list if "content" in c]
    # Remove duplicate or near-identical lines
    unique_lines = list({line.strip(): None for line in evidence_lines}.keys())[:15]

    # Extract hints from context
    context_text = "\n".join(unique_lines)
    if re.search(r"(workspace|git\+https|github|file:|local:|relative)", context_text, re.I):
        flags.append("explicit_private_source_detected")
    if re.search(r"(import|require|from\s+['\"])", context_text):
        flags.append("appears_to_be_imported")
    if not context_text.strip():
        flags.append("no_source_context_found")

    # Build context JSON
    context_str = json.dumps(context_list[:20], indent=2) if context_list else "[]"

    # Merge everything into a single query
    user_query = f"""
    Organization: {home_org}
    Package name: {package_name}
    Package type: {package_type}
    Observed signals: {flags}

    Source evidence:
    {context_str}

    Use all information above to classify this package according to the JSON format described.
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
                analysis['flags_detected'] = flags
                return analysis
            else:
                print(f"    [{Colors.YELLOW}WARN{Colors.RESET}] API request failed ({response.status_code}): {response.text}")
                if 400 <= response.status_code < 500: 
                    return None
        except requests.RequestException as e:
            print(f"    [{Colors.YELLOW}WARN{Colors.RESET}] API request exception: {e}")

        wait = (2 ** attempt)
        print(f"    [{Colors.BLUE}INFO{Colors.RESET}] Retrying in {wait}s...")
        time.sleep(wait)

    print(f"    [{Colors.RED}ERROR{Colors.RESET}] Failed to analyze '{package_name}' after {max_retries} attempts.")
    return None

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

