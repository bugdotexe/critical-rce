#!/usr/bin/env python3

"""
Smart LLM Dependency Confusion Triager - v2.0

A context-aware triager that uses LLM intelligence to classify dependency confusion risks
across diverse codebases without predefined categories.

Usage:
    python3 smart_triager.py /path/to/scan/output
    python3 smart_triager.py /tmp/project-scan

Features:
- No hardcoded classifications (Potential Vulnerability/False Positive)
- Adapts to different project types (web apps, libraries, internal tools, etc.)
- Considers project context and usage patterns
- Provides nuanced risk assessments
"""

import os
import sys
import json
import time
import requests
import csv
import subprocess
import re
import shutil
import shlex
from typing import List, Dict, Optional, Any, Tuple
from pathlib import Path

# --- Configuration ---
API_KEY = os.environ.get("OPENAI_API_KEY")
API_URL = "https://api.openai.com/v1/chat/completions"
MODEL_NAME = "gpt-4o"  # Using latest model for better reasoning
SEARCH_TIMEOUT = 20
MAX_CONTEXTS = 25
RATE_LIMIT_DELAY = 1.5  # Seconds between API calls

# ANSI color codes
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    RED = '\033[1;31m'
    GREEN = '\033[1;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[1;34m'
    CYAN = '\033[1;36m'
    MAGENTA = '\033[1;35m'
    WHITE = '\033[1;37m'
    GREY = '\033[0;37m'

USE_RIPGREP = False

# --- Adaptive System Prompt ---
SYSTEM_PROMPT = """
You are a senior security engineer performing dependency confusion analysis. Your task is to assess the risk level of available package names found in a codebase.

**CONTEXT ANALYSIS FRAMEWORK:**

Consider these factors when assessing risk:

1. **Package Name Characteristics:**
   - Does it sound internal/proprietary? (e.g., "company-auth", "internal-utils")
   - Is it generic/common? (e.g., "utils", "helpers", "common")
   - Does it contain organization/project-specific terms?
   - Is it scoped? (e.g., "@myorg/package")

2. **Codebase Context:**
   - How is the package used? (direct dependency, dev dependency, in scripts)
   - Is there evidence of private registry configuration?
   - Are there workspace references or local paths?
   - Is it in dependency files (package.json, requirements.txt) or just in code comments/docs?

3. **Project Type Considerations:**
   - Web applications vs libraries vs internal tools
   - Open source vs enterprise/internal projects
   - Modern vs legacy codebases

4. **Risk Indicators:**
   - Package names that match internal naming conventions
   - Missing private registry configurations
   - Direct usage without version pins or hashes
   - Presence in critical dependency files

**Provide a nuanced assessment without forcing binary classifications.**

Response Format (JSON only):
{
  "risk_level": "Critical/High/Medium/Low/Informational",
  "category": "Internal Package/Third Party/Unclear/Test/Utility/Scope Takeover/etc.",
  "confidence": "High/Medium/Low",
  "justification": "Detailed reasoning based on the evidence",
  "recommendation": "Specific action items",
  "requires_immediate_attention": true/false
}
"""

def detect_project_type(source_dir: str) -> Dict[str, Any]:
    """Automatically detect project characteristics."""
    project_info = {
        "type": "unknown",
        "ecosystems": [],
        "has_private_registry_config": False,
        "is_likely_internal": False,
        "characteristics": []
    }
    
    # Check for common project files
    files = []
    for root, dirs, filenames in os.walk(source_dir):
        files.extend(filenames)
        break  # Just top level for now
    
    file_set = set(files)
    
    # Detect ecosystems
    if 'package.json' in file_set:
        project_info["ecosystems"].append("npm")
        # Check for private registry config
        try:
            with open(os.path.join(source_dir, 'package.json'), 'r') as f:
                pkg_json = json.load(f)
                if any(key in pkg_json for key in ['publishConfig', '_authToken', 'registry']):
                    project_info["has_private_registry_config"] = True
        except:
            pass
    
    if 'requirements.txt' in file_set or 'setup.py' in file_set or 'Pipfile' in file_set:
        project_info["ecosystems"].append("python")
    
    if 'Gemfile' in file_set:
        project_info["ecosystems"].append("ruby")
    
    if 'pom.xml' in file_set:
        project_info["ecosystems"].append("java")
    
    if 'go.mod' in file_set:
        project_info["ecosystems"].append("go")
    
    # Detect project type
    if any(f in file_set for f in ['docker-compose.yml', 'Dockerfile', 'k8s']):
        project_info["characteristics"].append("containerized")
    
    if any(f in file_set for f in ['.github', '.gitlab-ci.yml', 'Jenkinsfile']):
        project_info["characteristics"].append("ci_cd")
    
    # Heuristics for internal projects
    internal_indicators = ['internal', 'proprietary', 'company', 'corp', 'enterprise']
    dir_name = os.path.basename(source_dir.rstrip('/'))
    if any(indicator in dir_name.lower() for indicator in internal_indicators):
        project_info["is_likely_internal"] = True
    
    if project_info["ecosystems"]:
        project_info["type"] = "application"
    elif any(f.endswith('.md') for f in files):
        project_info["type"] = "documentation"
    
    return project_info

def check_for_ripgrep() -> bool:
    """Check if ripgrep is available."""
    return bool(shutil.which("rg"))

def strip_ansi_codes(text: str) -> str:
    """Remove ANSI escape codes from text."""
    if not text:
        return ""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def validate_package_name(package_name: str) -> bool:
    """Validate package name for safety."""
    if not package_name or len(package_name) > 200:
        return False
    dangerous_patterns = [';', '|', '&', '`', '$', '>', '<', '\n', '\r']
    return not any(pattern in package_name for pattern in dangerous_patterns)

def safe_file_read(file_path: str) -> Optional[str]:
    """Safely read file with error handling."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except Exception as e:
        print(f"[{Colors.RED}ERROR{Colors.RESET}] Failed to read {file_path}: {e}")
        return None

def find_package_context(package_name: str, search_dir: str) -> List[Dict[str, Any]]:
    """Find all occurrences of package name with enhanced context gathering."""
    contexts = []
    
    # Try multiple search strategies
    search_patterns = [
        package_name,  # Exact match
        f'"{package_name}"',  # Quoted (common in package.json)
        f"'{package_name}'",  # Single quoted
        f"\\b{re.escape(package_name)}\\b",  # Word boundary for regex
    ]
    
    for pattern in search_patterns[:2]:  # Just use first two for performance
        try:
            if USE_RIPGREP:
                cmd = [
                    "rg", "-n", "-i", "--no-heading", "--no-ignore",
                    "-g", "!*.log", "-g", "!*.min.js", "-g", "!node_modules/",
                    "-g", "!*.pyc", "-g", "!__pycache__/", "-g", "!*.git/",
                    pattern, search_dir
                ]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=SEARCH_TIMEOUT)
            else:
                grep_cmd = f"grep -rni {shlex.quote(pattern)} {shlex.quote(search_dir)}"
                exclude_cmd = "grep -vE '(node_modules|\\.log|\\.min\\.js|\\.pyc|__pycache__|\\.git)'"
                full_cmd = f"{grep_cmd} | {exclude_cmd}"
                result = subprocess.run(full_cmd, shell=True, capture_output=True, text=True, timeout=SEARCH_TIMEOUT)
            
            if result.stdout:
                for line in result.stdout.strip().split('\n'):
                    if not line.strip():
                        continue
                    
                    match = re.match(r'([^:]+):(\d+):(.*)', line)
                    if match:
                        file_path, line_num_str, content = match.groups()
                        
                        # Skip binary files and very long lines
                        if len(content) > 500:
                            content = content[:500] + "..."
                        
                        contexts.append({
                            "file": os.path.relpath(file_path, search_dir),
                            "line": int(line_num_str),
                            "content": content.strip(),
                            "file_type": Path(file_path).suffix.lower()
                        })
                        
                        if len(contexts) >= MAX_CONTEXTS:
                            break
                
        except subprocess.TimeoutExpired:
            continue
        except Exception:
            continue
        
        if contexts:
            break
    
    return contexts

def analyze_package_with_llm(package_name: str, package_type: str, 
                           project_context: Dict, code_context: List[Dict],
                           max_retries: int = 3) -> Optional[Dict[str, Any]]:
    """Analyze package with contextual LLM reasoning."""
    print(f"  [{Colors.CYAN}ANALYZE{Colors.RESET}] {package_type}: {Colors.BOLD}{package_name}{Colors.RESET}")
    
    # Prepare enhanced context
    analysis_context = {
        "package": package_name,
        "ecosystem": package_type,
        "project_characteristics": project_context,
        "usage_contexts": code_context,
        "total_contexts_found": len(code_context)
    }
    
    user_prompt = f"""
Analyze this package for dependency confusion risk:

**Package Details:**
- Name: {package_name}
- Ecosystem: {package_type}
- Project Type: {project_context.get('type', 'unknown')}
- Ecosystems Detected: {', '.join(project_context.get('ecosystems', []))}
- Private Registry Configured: {project_context.get('has_private_registry_config', False)}
- Likely Internal Project: {project_context.get('is_likely_internal', False)}

**Usage Context ({len(code_context)} instances found):**
{json.dumps(code_context, indent=2) if code_context else "No usage context found in codebase"}

Provide a nuanced risk assessment based on the package characteristics and how it's used in this specific project context.
"""

    payload = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt}
        ],
        "response_format": {"type": "json_object"},
        "temperature": 0.2,  # Slightly higher for nuanced reasoning
        "max_tokens": 800
    }

    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {API_KEY}'
    }

    for attempt in range(max_retries):
        try:
            response = requests.post(API_URL, headers=headers, data=json.dumps(payload), timeout=90)
            if response.status_code == 200:
                result = response.json()
                json_text = result.get('choices', [{}])[0].get('message', {}).get('content', '{}')
                
                try:
                    analysis = json.loads(json_text)
                    # Validate required fields
                    required_fields = ['risk_level', 'category', 'confidence', 'justification', 'recommendation']
                    if all(field in analysis for field in required_fields):
                        analysis['package_name'] = package_name
                        analysis['package_type'] = package_type
                        analysis['contexts_analyzed'] = len(code_context)
                        return analysis
                    else:
                        print(f"    [{Colors.YELLOW}WARN{Colors.RESET}] Missing fields in LLM response")
                        return None
                except json.JSONDecodeError as e:
                    print(f"    [{Colors.RED}ERROR{Colors.RESET}] JSON parse error: {e}")
                    return None
                    
            elif response.status_code == 429:
                wait_time = (2 ** attempt) * 10
                print(f"    [{Colors.YELLOW}RATE_LIMIT{Colors.RESET}] Waiting {wait_time}s...")
                time.sleep(wait_time)
            else:
                print(f"    [{Colors.RED}ERROR{Colors.RESET}] API error {response.status_code}")
                if attempt == max_retries - 1:
                    return None
                    
        except requests.RequestException as e:
            print(f"    [{Colors.YELLOW}WARN{Colors.RESET}] Request failed: {e}")
            if attempt == max_retries - 1:
                return None
        
        time.sleep(2 ** attempt)  # Exponential backoff

    return None

def load_potential_packages(source_dir: str) -> List[Tuple[str, str]]:
    """Load packages from all potential files."""
    packages = []
    dep_dir = os.path.join(source_dir, "DEP")
    
    if not os.path.isdir(dep_dir):
        print(f"[{Colors.RED}ERROR{Colors.RESET}] DEP directory not found")
        return packages

    for potential_file in Path(dep_dir).glob("*.potential"):
        package_type = potential_file.stem  # npm, pip, gem, etc.
        
        content = safe_file_read(str(potential_file))
        if content:
            for line in content.splitlines():
                package_name = strip_ansi_codes(line.strip())
                if package_name and validate_package_name(package_name):
                    packages.append((package_name, package_type))
    
    return packages

def generate_comprehensive_report(results: List[Dict], report_path: str, project_info: Dict):
    """Generate detailed analysis report."""
    try:
        with open(report_path, 'w', newline='') as f:
            fieldnames = [
                'package_name', 'package_type', 'risk_level', 'category', 
                'confidence', 'requires_immediate_attention', 'contexts_analyzed',
                'justification', 'recommendation', 'timestamp'
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for result in results:
                row = {
                    'package_name': result.get('package_name', ''),
                    'package_type': result.get('package_type', ''),
                    'risk_level': result.get('risk_level', 'Unknown'),
                    'category': result.get('category', 'Unknown'),
                    'confidence': result.get('confidence', 'Unknown'),
                    'requires_immediate_attention': result.get('requires_immediate_attention', False),
                    'contexts_analyzed': result.get('contexts_analyzed', 0),
                    'justification': result.get('justification', ''),
                    'recommendation': result.get('recommendation', ''),
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                }
                writer.writerow(row)
                
        print(f"[{Colors.GREEN}SUCCESS{Colors.RESET}] Report saved: {report_path}")
    except Exception as e:
        print(f"[{Colors.RED}ERROR{Colors.RESET}] Failed to write report: {e}")

def print_intelligent_summary(results: List[Dict], project_info: Dict):
    """Print adaptive summary based on findings."""
    if not results:
        print(f"\n[{Colors.YELLOW}INFO{Colors.RESET}] No packages were analyzed")
        return
    
    # Dynamic risk categorization
    risk_groups = {}
    for result in results:
        risk_level = result.get('risk_level', 'Unknown')
        if risk_level not in risk_groups:
            risk_groups[risk_level] = []
        risk_groups[risk_level].append(result)
    
    # Count immediate attention items
    urgent_count = sum(1 for r in results if r.get('requires_immediate_attention', False))
    
    print(f"\n{Colors.CYAN}{'='*70}{Colors.RESET}")
    print(f"{Colors.BOLD}           SMART DEPENDENCY TRIAGE SUMMARY{Colors.RESET}")
    print(f"{Colors.CYAN}{'='*70}{Colors.RESET}")
    print(f"  Project Type: {Colors.BOLD}{project_info.get('type', 'Unknown')}{Colors.RESET}")
    print(f"  Ecosystems: {Colors.BOLD}{', '.join(project_info.get('ecosystems', ['Unknown']))}{Colors.RESET}")
    print(f"  Private Registry: {Colors.BOLD}{project_info.get('has_private_registry_config', False)}{Colors.RESET}")
    print(f"  Total Packages Analyzed: {Colors.BOLD}{len(results)}{Colors.RESET}")
    print(f"  Requires Immediate Attention: {Colors.RED if urgent_count > 0 else Colors.GREEN}{urgent_count}{Colors.RESET}")
    print(f"{Colors.CYAN}{'-'*70}{Colors.RESET}")
    
    # Display findings by risk level
    risk_order = ['Critical', 'High', 'Medium', 'Low', 'Informational', 'Unknown']
    for risk in risk_order:
        if risk in risk_groups:
            count = len(risk_groups[risk])
            color = {
                'Critical': Colors.RED,
                'High': Colors.RED,
                'Medium': Colors.YELLOW,
                'Low': Colors.GREEN,
                'Informational': Colors.BLUE,
                'Unknown': Colors.GREY
            }.get(risk, Colors.WHITE)
            
            print(f"  {color}{risk}: {count} packages{Colors.RESET}")
    
    print(f"{Colors.CYAN}{'='*70}{Colors.RESET}")
    
    # Show top concerns
    critical_high = [r for r in results if r.get('risk_level') in ['Critical', 'High']]
    if critical_high:
        print(f"\n{Colors.BOLD}TOP CONCERNS:{Colors.RESET}")
        for concern in critical_high[:5]:  # Show top 5
            urgency = "🚨 " if concern.get('requires_immediate_attention') else ""
            print(f"  {urgency}{Colors.RED}{concern['package_name']}{Colors.RESET} ({concern['package_type']})")
            print(f"     Risk: {concern['risk_level']} | Confidence: {concern['confidence']}")
            print(f"     Category: {concern['category']}")
            print(f"     Justification: {concern['justification'][:100]}...")
            print()

def main():
    """Main execution function."""
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <scan_output_directory>")
        print(f"Example: python3 {sys.argv[0]} /tmp/your-project-scan")
        sys.exit(1)
    
    source_dir = sys.argv[1]
    
    if not os.path.isdir(source_dir):
        print(f"[{Colors.RED}ERROR{Colors.RESET}] Directory not found: {source_dir}")
        sys.exit(1)
    
    if not API_KEY:
        print(f"[{Colors.RED}ERROR{Colors.RESET}] OPENAI_API_KEY environment variable required")
        sys.exit(1)
    
    global USE_RIPGREP
    USE_RIPGREP = check_for_ripgrep()
    if USE_RIPGREP:
        print(f"[{Colors.GREEN}INFO{Colors.RESET}] Using ripgrep for fast context search")
    
    print(f"[{Colors.BLUE}INFO{Colors.RESET}] Starting smart dependency triage...")
    print(f"[{Colors.BLUE}INFO{Colors.RESET}] Analyzing: {Colors.BOLD}{source_dir}{Colors.RESET}")
    
    # Phase 1: Project Analysis
    print(f"[{Colors.BLUE}INFO{Colors.RESET}] Analyzing project characteristics...")
    project_info = detect_project_type(source_dir)
    print(f"       Type: {project_info['type']}")
    print(f"       Ecosystems: {', '.join(project_info['ecosystems'])}")
    print(f"       Private Registry: {project_info['has_private_registry_config']}")
    
    # Phase 2: Load Packages
    packages = load_potential_packages(source_dir)
    if not packages:
        print(f"[{Colors.YELLOW}WARN{Colors.RESET}] No potential packages found")
        sys.exit(0)
    
    print(f"[{Colors.BLUE}INFO{Colors.RESET}] Found {len(packages)} packages to analyze")
    
    # Phase 3: Smart Analysis
    results = []
    for i, (package_name, package_type) in enumerate(packages, 1):
        print(f"[{Colors.BLUE}INFO{Colors.RESET}] Progress: {i}/{len(packages)}")
        
        # Gather context
        contexts = find_package_context(package_name, source_dir)
        
        # Analyze with LLM
        analysis = analyze_package_with_llm(package_name, package_type, project_info, contexts)
        
        if analysis:
            results.append(analysis)
        else:
            # Fallback analysis for failed attempts
            results.append({
                'package_name': package_name,
                'package_type': package_type,
                'risk_level': 'Unknown',
                'category': 'Analysis Failed',
                'confidence': 'Low',
                'justification': 'LLM analysis failed',
                'recommendation': 'Manual review required',
                'requires_immediate_attention': False,
                'contexts_analyzed': len(contexts)
            })
        
        # Rate limiting
        time.sleep(RATE_LIMIT_DELAY)
    
    # Phase 4: Reporting
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    report_dir = os.path.join(source_dir, "smart_analysis")
    os.makedirs(report_dir, exist_ok=True)
    
    report_path = os.path.join(report_dir, f"dependency_analysis_{timestamp}.csv")
    generate_comprehensive_report(results, report_path, project_info)
    
    # Final Summary
    print_intelligent_summary(results, project_info)
    
    print(f"\n[{Colors.GREEN}SUCCESS{Colors.RESET}] Smart triage completed!")
    print(f"[{Colors.GREEN}INFO{Colors.RESET}] Detailed report: {report_path}")

if __name__ == "__main__":
    main()
