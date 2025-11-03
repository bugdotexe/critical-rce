#!/usr/bin/env python3

"""
Smart Dependency Confusion Triager v3.0
Python version with better performance and accuracy
"""

import os
import sys
import json
import subprocess
import re
import time
import argparse
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import openai
from openai import OpenAI
import tiktoken

# ANSI colors for output
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    RED = '\033[1;31m'
    GREEN = '\033[1;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[1;34m'
    CYAN = '\033[1;36m'
    MAGENTA = '\033[1;35m'

def notice(msg):
    print(f"{Colors.BLUE}[INFO]{Colors.RESET} {msg}")

def warn(msg):
    print(f"{Colors.YELLOW}[WARN]{Colors.RESET} {msg}")

def error(msg):
    print(f"{Colors.RED}[ERROR]{Colors.RESET} {msg}")

def success(msg):
    print(f"{Colors.GREEN}[SUCCESS]{Colors.RESET} {msg}")

class DependencyTriager:
    def __init__(self, target_dir: str, output_dir: str, model: str = "gpt-4o"):
        self.target_dir = Path(target_dir)
        self.output_dir = Path(output_dir)
        self.model = model
        self.client = None
        self.encoding = tiktoken.encoding_for_model("gpt-4")
        
        # Create output directories
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / "contexts").mkdir(exist_ok=True)
        (self.output_dir / "analysis").mkdir(exist_ok=True)
        (self.output_dir / "reports").mkdir(exist_ok=True)
        
        self.setup_openai()
    
    def setup_openai(self):
        """Initialize OpenAI client"""
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            error("OPENAI_API_KEY environment variable required")
            sys.exit(1)
        
        self.client = OpenAI(api_key=api_key)
        
        # Test the connection
        try:
            self.client.models.list()
        except Exception as e:
            error(f"OpenAI API connection failed: {e}")
            sys.exit(1)
    
    def count_tokens(self, text: str) -> int:
        """Count tokens in text"""
        return len(self.encoding.encode(text))
    
    def truncate_text(self, text: str, max_tokens: int = 8000) -> str:
        """Truncate text to fit within token limit"""
        tokens = self.encoding.encode(text)
        if len(tokens) <= max_tokens:
            return text
        
        truncated_tokens = tokens[:max_tokens]
        return self.encoding.decode(truncated_tokens) + "\n...[truncated due to length]"
    
    def run_ripgrep(self, pattern: str, file_types: List[str] = None, max_results: int = 100) -> List[str]:
        """Run ripgrep with fixed string search"""
        cmd = ["rg", "-F", "-n", "--no-heading", "--color=never"]
        
        # Add file type filters if specified
        if file_types:
            for file_type in file_types:
                cmd.extend(["-t", file_type])
        
        cmd.extend(["--max-count", str(max_results), pattern, str(self.target_dir)])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                return result.stdout.strip().split('\n')
            elif result.returncode == 1:  # No results
                return []
            else:
                warn(f"ripgrep returned {result.returncode} for pattern: {pattern}")
                return []
        except subprocess.TimeoutExpired:
            warn(f"ripgrep timed out for pattern: {pattern}")
            return []
        except Exception as e:
            warn(f"ripgrep failed for {pattern}: {e}")
            return []
    
    def extract_deep_context(self, package_name: str, package_type: str) -> str:
        """Extract comprehensive context using ripgrep"""
        context_parts = []
        
        # Header
        context_parts.append(f"# Deep Context Analysis for: {package_name} ({package_type})")
        context_parts.append(f"## Analysis Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        # Repository structure
        context_parts.append("## Repository Structure Overview")
        context_parts.append("```")
        try:
            files = list(self.target_dir.rglob("*"))
            file_extensions = {'.json', '.js', '.ts', '.py', '.rb', '.go', '.java', 
                             '.toml', '.yaml', '.yml', '.md', '.txt', 'package.json',
                             'requirements.txt', 'Gemfile', 'go.mod', 'pom.xml', 'Cargo.toml'}
            
            relevant_files = []
            for f in files:
                if f.is_file() and (f.suffix in file_extensions or f.name in file_extensions):
                    relevant_files.append(str(f.relative_to(self.target_dir)))
                    if len(relevant_files) >= 50:
                        break
            
            context_parts.extend(relevant_files[:50])
        except Exception as e:
            warn(f"Failed to get repository structure: {e}")
        
        context_parts.append("```\n")
        
        # All code references using fixed string search
        context_parts.append("## All Code References (ripgrep -F analysis)")
        context_parts.append("```")
        
        file_types = ["json", "js", "ts", "py", "rb", "go", "java", "toml", "yaml", "yml", "md", "txt"]
        results = self.run_ripgrep(package_name, file_types, max_results=100)
        context_parts.extend(results[:100])
        context_parts.append("```\n")
        
        # Ecosystem-specific analysis
        ecosystem_context = self.get_ecosystem_context(package_name, package_type)
        if ecosystem_context:
            context_parts.append(ecosystem_context)
        
        # Source analysis
        context_parts.append("## Source Analysis")
        
        # Git URLs
        context_parts.append("### Git URLs:")
        git_results = self.run_ripgrep(f"git.*{package_name}", max_results=20)
        context_parts.extend(git_results[:10])
        
        # Local paths
        context_parts.append("### Local Paths:")
        local_patterns = [f"file:.*{package_name}", f"path:.*{package_name}", f"\./.*{package_name}"]
        for pattern in local_patterns:
            results = self.run_ripgrep(pattern, max_results=10)
            context_parts.extend(results[:5])
        
        # Private registries
        context_parts.append("### Private Registries:")
        registry_results = self.run_ripgrep(f"registry.*{package_name}", max_results=10)
        context_parts.extend(registry_results[:5])
        
        # Import/usage patterns
        context_parts.append("## Import/Usage Patterns")
        usage_patterns = [f"import.*{package_name}", f"require.*{package_name}", f"from.*{package_name}"]
        for pattern in usage_patterns:
            results = self.run_ripgrep(pattern, max_results=15)
            context_parts.extend(results[:10])
        
        full_context = "\n".join(context_parts)
        
        # Token-based truncation
        if self.count_tokens(full_context) > 12000:
            full_context = self.truncate_text(full_context, 10000)
            full_context += "\n\n[Context truncated due to length limitations]"
        
        return full_context
    
    def get_ecosystem_context(self, package_name: str, package_type: str) -> str:
        """Get ecosystem-specific context"""
        context_parts = []
        
        if package_type == "npm":
            context_parts.append("## NPM-Specific Analysis")
            
            # Find package.json files
            pkg_files = list(self.target_dir.rglob("package.json"))
            for pkg_file in pkg_files[:5]:  # Limit to 5 files
                try:
                    with open(pkg_file, 'r') as f:
                        content = f.read()
                        if package_name in content:
                            context_parts.append(f"### File: {pkg_file.relative_to(self.target_dir)}")
                            context_parts.append("```json")
                            # Extract relevant parts
                            lines = content.split('\n')
                            for i, line in enumerate(lines):
                                if package_name in line:
                                    start = max(0, i-2)
                                    end = min(len(lines), i+3)
                                    context_parts.extend(lines[start:end])
                                    context_parts.append("...")
                                    break
                            context_parts.append("```")
                except Exception as e:
                    continue
        
        elif package_type == "pip":
            context_parts.append("## Python-Specific Analysis")
            req_files = list(self.target_dir.rglob("requirements*.txt"))
            req_files.extend(list(self.target_dir.rglob("Pipfile")))
            req_files.extend(list(self.target_dir.rglob("pyproject.toml")))
            
            for req_file in req_files[:3]:
                try:
                    with open(req_file, 'r') as f:
                        content = f.read()
                        if package_name in content:
                            context_parts.append(f"### File: {req_file.relative_to(self.target_dir)}")
                            context_parts.append("```")
                            lines = content.split('\n')
                            for line in lines:
                                if package_name in line:
                                    context_parts.append(line)
                            context_parts.append("```")
                except Exception:
                    continue
        
        # Add other ecosystems as needed...
        
        if context_parts:
            return "\n".join(context_parts) + "\n"
        return ""
    
    def analyze_with_llm(self, package_name: str, package_type: str, context: str) -> Optional[Dict]:
        """Analyze package with OpenAI API"""
        prompt = f"""Analyze this dependency confusion scenario based on the comprehensive codebase context provided.

## Package Information
- Name: {package_name}
- Ecosystem: {package_type}

## Comprehensive Codebase Context
{context}

## Analysis Task
Based on the actual codebase context above, determine if this package represents a real dependency confusion vulnerability.

Provide your analysis in JSON format with the following structure:
{{
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW|NONE",
  "confidence": "HIGH|MEDIUM|LOW", 
  "vulnerability_status": "CONFIRMED|LIKELY|UNLIKELY|FALSE_POSITIVE",
  "actual_source": "public_registry|git_url|local_path|workspace|private_registry|unknown",
  "evidence_found": true|false,
  "technical_analysis": "Detailed explanation of usage context and why this is/isn't vulnerable",
  "recommendation": "Specific remediation steps if needed"
}}

Focus on:
- Actual usage patterns found in the codebase
- Source identification (public registry vs private/git/local)
- Project-specific dependency patterns
- Evidence of workspace, local path, or private registry usage"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a senior security engineer with deep expertise in dependency management and supply chain security. Analyze codebase context thoroughly and provide evidence-based assessments. Focus on actual usage patterns and sourcing methods found in the code. Always respond with valid JSON."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                response_format={"type": "json_object"},
                temperature=0.1,
                max_tokens=1500
            )
            
            analysis_text = response.choices[0].message.content
            analysis = json.loads(analysis_text)
            
            # Add metadata
            analysis["package_name"] = package_name
            analysis["package_type"] = package_type
            analysis["timestamp"] = time.strftime('%Y-%m-%d %H:%M:%S')
            
            return analysis
            
        except json.JSONDecodeError as e:
            error(f"Failed to parse JSON response for {package_name}: {e}")
            # Try to extract JSON from response
            try:
                json_match = re.search(r'\{.*\}', analysis_text, re.DOTALL)
                if json_match:
                    analysis = json.loads(json_match.group())
                    analysis["package_name"] = package_name
                    analysis["package_type"] = package_type
                    analysis["timestamp"] = time.strftime('%Y-%m-%d %H:%M:%S')
                    analysis["parse_warning"] = "Response was extracted from text"
                    return analysis
            except:
                pass
                
            return None
        except Exception as e:
            error(f"API call failed for {package_name}: {e}")
            return None
    
    def load_potential_packages(self) -> List[Tuple[str, str]]:
        """Load packages from .potential files"""
        dep_dir = self.target_dir / "DEP"
        if not dep_dir.exists():
            error(f"DEP directory not found: {dep_dir}")
            sys.exit(1)
        
        packages = []
        for potential_file in dep_dir.glob("*.potential"):
            package_type = potential_file.stem
            try:
                with open(potential_file, 'r') as f:
                    for line in f:
                        package_name = line.strip()
                        if package_name:
                            packages.append((package_name, package_type))
            except Exception as e:
                warn(f"Failed to read {potential_file}: {e}")
        
        return packages
    
    def process_packages(self):
        """Process all potential packages"""
        packages = self.load_potential_packages()
        
        if not packages:
            warn("No potential packages found")
            return
        
        notice(f"Found {len(packages)} potential packages to analyze")
        
        success_count = 0
        fail_count = 0
        
        for i, (package_name, package_type) in enumerate(packages, 1):
            print(f"[{i}/{len(packages)}] ", end="")
            notice(f"Analyzing: {package_name}")
            
            # Extract context
            print("    Extracting context...", end="", flush=True)
            context = self.extract_deep_context(package_name, package_type)
            print("done")
            
            # Save context for debugging
            safe_name = re.sub(r'[^a-zA-Z0-9._-]', '_', package_name)
            context_file = self.output_dir / "contexts" / f"{package_type}_{safe_name}.md"
            with open(context_file, 'w') as f:
                f.write(context)
            
            # Analyze with LLM
            print("    LLM analysis...", end="", flush=True)
            analysis = self.analyze_with_llm(package_name, package_type, context)
            
            if analysis:
                # Save analysis
                analysis_file = self.output_dir / "analysis" / f"{package_type}_{safe_name}.json"
                with open(analysis_file, 'w') as f:
                    json.dump(analysis, f, indent=2)
                print("done")
                success_count += 1
            else:
                print("failed")
                fail_count += 1
            
            # Rate limiting
            time.sleep(2)
        
        notice(f"Analysis completed: {success_count} successful, {fail_count} failed")
    
    def generate_report(self):
        """Generate comprehensive report"""
        analysis_dir = self.output_dir / "analysis"
        report_file = self.output_dir / "reports" / f"dependency_triage_report_{time.strftime('%Y%m%d_%H%M%S')}.md"
        
        notice("Generating intelligent triage report...")
        
        with open(report_file, 'w') as f:
            f.write("# Dependency Confusion Triage Report\n")
            f.write(f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Target:** {self.target_dir}\n")
            f.write(f"**Model:** {self.model}\n\n")
            
            analyzed_count = 0
            vulnerable_count = 0
            false_positive_count = 0
            uncertain_count = 0
            error_count = 0
            
            # Process all analysis files
            for analysis_file in analysis_dir.glob("*.json"):
                analyzed_count += 1
                
                with open(analysis_file, 'r') as af:
                    try:
                        analysis = json.load(af)
                        package_name = analysis.get("package_name", "unknown")
                        package_type = analysis.get("package_type", "unknown")
                        risk_level = analysis.get("risk_level", "UNKNOWN").upper()
                        
                        if risk_level in ["CRITICAL", "HIGH"]:
                            vulnerable_count += 1
                            f.write(f"## 🔴 {package_name} ({package_type}) - {risk_level}\n")
                        elif risk_level in ["LOW", "NONE"]:
                            false_positive_count += 1
                            f.write(f"## ✅ {package_name} ({package_type}) - {risk_level}\n")
                        else:
                            uncertain_count += 1
                            f.write(f"## ⚠️  {package_name} ({package_type}) - {risk_level}\n")
                        
                        f.write("```json\n")
                        json.dump(analysis, f, indent=2)
                        f.write("\n```\n\n")
                        
                    except Exception as e:
                        error_count += 1
                        f.write(f"## ❌ {analysis_file.stem} - PARSE ERROR\n")
                        f.write(f"Error: {e}\n\n")
            
            # Summary
            f.write("# Executive Summary\n\n")
            f.write("| Category | Count | Percentage |\n")
            f.write("|----------|-------|------------|\n")
            
            if analyzed_count > 0:
                vulnerable_pct = (vulnerable_count / analyzed_count) * 100
                false_positive_pct = (false_positive_count / analyzed_count) * 100
                uncertain_pct = (uncertain_count / analyzed_count) * 100
                error_pct = (error_count / analyzed_count) * 100
                
                f.write(f"| 🔴 Potentially Vulnerable | {vulnerable_count} | {vulnerable_pct:.1f}% |\n")
                f.write(f"| ✅ False Positives | {false_positive_count} | {false_positive_pct:.1f}% |\n")
                f.write(f"| ⚠️  Uncertain/Manual Review | {uncertain_count} | {uncertain_pct:.1f}% |\n")
                f.write(f"| ❌ Analysis Errors | {error_count} | {error_pct:.1f}% |\n")
            else:
                f.write("| 🔴 Potentially Vulnerable | 0 | 0% |\n")
                f.write("| ✅ False Positives | 0 | 0% |\n")
                f.write("| ⚠️  Uncertain/Manual Review | 0 | 0% |\n")
                f.write("| ❌ Analysis Errors | 0 | 0% |\n")
            
            f.write(f"| **Total Analyzed** | **{analyzed_count}** | **100%** |\n")
        
        success(f"Comprehensive report generated: {report_file}")
        
        # Terminal summary
        print()
        warn("=== TRIAGE SUMMARY ===")
        print(f"🔴 Potentially Vulnerable: {Colors.RED}{vulnerable_count}{Colors.RESET}")
        print(f"✅ False Positives: {Colors.GREEN}{false_positive_count}{Colors.RESET}")
        print(f"⚠️  Need Manual Review: {Colors.YELLOW}{uncertain_count}{Colors.RESET}")
        print(f"❌ Analysis Errors: {Colors.MAGENTA}{error_count}{Colors.RESET}")
        print(f"📊 Total Analyzed: {Colors.BLUE}{analyzed_count}{Colors.RESET}")
        print()

def main():
    parser = argparse.ArgumentParser(description="Smart Dependency Confusion Triager")
    parser.add_argument("-t", "--target", required=True, help="Target directory to analyze")
    parser.add_argument("-o", "--output", help="Output directory (default: <target>/llm_triage_<timestamp>)")
    parser.add_argument("-m", "--model", default="gpt-4o", help="OpenAI model to use (default: gpt-4o)")
    
    args = parser.parse_args()
    
    target_dir = Path(args.target)
    if not target_dir.exists():
        error(f"Target directory not found: {target_dir}")
        sys.exit(1)
    
    if args.output:
        output_dir = Path(args.output)
    else:
        output_dir = target_dir / f"llm_triage_{time.strftime('%Y%m%d_%H%M%S')}"
    
    # Check for required tools
    try:
        subprocess.run(["rg", "--version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        error("ripgrep (rg) is required but not installed or not in PATH")
        sys.exit(1)
    
    notice(f"Starting advanced LLM triage for: {target_dir}")
    notice(f"Output directory: {output_dir}")
    notice(f"Using model: {args.model}")
    notice("Using ripgrep for context analysis")
    
    triager = DependencyTriager(target_dir, output_dir, args.model)
    triager.process_packages()
    triager.generate_report()
    
    success("Advanced triage completed successfully!")
    notice(f"Full analysis available in: {output_dir}")
    notice(f"Context files: {output_dir}/contexts/")
    notice(f"LLM analysis: {output_dir}/analysis/")

if __name__ == "__main__":
    main()
