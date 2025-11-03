#!/bin/bash

# Smart Dependency Confusion Triager v2.1
# Fixed version with better error handling and sanitization

notice() { printf '\e[1;34m[INFO]\e[0m %s\n' "$*"; }
warn()   { printf '\e[1;33m[WARN]\e[0m %s\n' "$*"; }
err()    { printf '\e[1;31m[ERROR]\e[0m %s\n' "$*"; }
success() { printf '\e[1;32m[SUCCESS]\e[0m %s\n' "$*"; }

# Sanitize filename
sanitize_filename() {
    echo "$1" | sed 's/[^a-zA-Z0-9._-]/_/g'
}

# Check dependencies
check_deps() {
    if ! command -v rg &> /dev/null; then
        err "ripgrep (rg) is required but not installed"
        exit 1
    fi
    
    if ! command -v jq &> /dev/null; then
        err "jq is required but not installed"
        exit 1
    fi
    
    if [ -z "$OPENAI_API_KEY" ]; then
        err "OPENAI_API_KEY environment variable required"
        exit 1
    fi
}

# Parse arguments
TARGET_DIR=""
OUTPUT_DIR=""
MODEL="gpt-4o"

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        -t|--target)
            TARGET_DIR="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -m|--model)
            MODEL="$2"
            shift 2
            ;;
        *)
            err "Usage: $0 -t <target_directory> [-o <output_directory>] [-m <model>]"
            exit 1
            ;;
    esac
done

if [ -z "$TARGET_DIR" ] || [ ! -d "$TARGET_DIR" ]; then
    err "Target directory required and must exist"
    exit 1
fi

if [ -z "$OUTPUT_DIR" ]; then
    OUTPUT_DIR="$TARGET_DIR/llm_triage_$(date +%Y%m%d_%H%M%S)"
fi

mkdir -p "$OUTPUT_DIR"
check_deps

notice "Starting advanced LLM triage for: $TARGET_DIR"
notice "Output directory: $OUTPUT_DIR"
notice "Using model: $MODEL"
notice "Using ripgrep for context analysis"

# Enhanced context extraction with ripgrep
extract_deep_context() {
    local package_name="$1"
    local package_type="$2"
    local context_file="$3"
    
    # Create directory if it doesn't exist
    mkdir -p "$(dirname "$context_file")"
    
    echo "# Deep Context Analysis for: $package_name ($package_type)" > "$context_file"
    echo "## Analysis Date: $(date)" >> "$context_file"
    echo "" >> "$context_file"
    
    # Escape package name for regex
    local escaped_pkg=$(printf '%s' "$package_name" | sed 's/[][\.*^$(){}?+|]/\\&/g')
    
    echo "## Repository Structure Overview" >> "$context_file"
    echo '```' >> "$context_file"
    find "$TARGET_DIR" -type f \( -name "*.json" -o -name "*.js" -o -name "*.ts" -o -name "*.py" -o -name "*.rb" -o -name "*.go" -o -name "*.java" -o -name "*.toml" -o -name "*.yaml" -o -name "*.yml" -o -name "*.md" -o -name "*.txt" \) 2>/dev/null | \
        head -50 | sed "s|$TARGET_DIR/||" >> "$context_file"
    echo '```' >> "$context_file"
    echo "" >> "$context_file"
    
    echo "## All Code References (ripgrep analysis)" >> "$context_file"
    echo '```' >> "$context_file"
    rg --color=never --no-heading --line-number --max-count=50 --type=json --type=js --type=ts --type=py --type=rb --type=go --type=java --type=toml --type=yaml --type=yml --type=md --type=txt "$escaped_pkg" "$TARGET_DIR" 2>/dev/null | \
        head -100 >> "$context_file" 2>/dev/null
    echo '```' >> "$context_file"
    echo "" >> "$context_file"
    
    # Ecosystem-specific deep analysis
    case "$package_type" in
        "npm")
            echo "## NPM-Specific Analysis" >> "$context_file"
            echo "### package.json files containing package:" >> "$context_file"
            rg --color=never -l "$escaped_pkg" "$TARGET_DIR" -g "package.json" 2>/dev/null | while read -r file; do
                echo "**File:** $file" >> "$context_file"
                echo '```json' >> "$context_file"
                if command -v jq >/dev/null 2>&1; then
                    jq 'with_entries(select([.key] | inside(["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"])))' "$file" 2>/dev/null | \
                        grep -A2 -B2 "$package_name" >> "$context_file" 2>/dev/null || \
                        rg --color=never -A3 -B3 "$escaped_pkg" "$file" 2>/dev/null >> "$context_file" 2>/dev/null
                else
                    rg --color=never -A3 -B3 "$escaped_pkg" "$file" 2>/dev/null >> "$context_file" 2>/dev/null
                fi
                echo '```' >> "$context_file"
            done
            
            echo "### Workspace Configuration:" >> "$context_file"
            rg --color=never -A2 -B2 "workspace:" "$TARGET_DIR" -g "package.json" 2>/dev/null >> "$context_file" 2>/dev/null
            ;;
            
        "pip")
            echo "## Python-Specific Analysis" >> "$context_file"
            echo "### Requirements files:" >> "$context_file"
            rg --color=never -l "$escaped_pkg" "$TARGET_DIR" -g "requirements*.txt" -g "Pipfile" -g "pyproject.toml" -g "setup.py" 2>/dev/null | while read -r file; do
                echo "**File:** $file" >> "$context_file"
                echo '```' >> "$context_file"
                rg --color=never -A2 -B2 "$escaped_pkg" "$file" 2>/dev/null >> "$context_file" 2>/dev/null
                echo '```' >> "$context_file"
            done
            ;;
            
        "gem")
            echo "## Ruby-Specific Analysis" >> "$context_file"
            rg --color=never -l "$escaped_pkg" "$TARGET_DIR" -g "Gemfile" -g "*.gemspec" 2>/dev/null | while read -r file; do
                echo "**File:** $file" >> "$context_file"
                echo '```ruby' >> "$context_file"
                rg --color=never -A3 -B3 "$escaped_pkg" "$file" 2>/dev/null >> "$context_file" 2>/dev/null
                echo '```' >> "$context_file"
            done
            ;;
            
        "go")
            echo "## Go-Specific Analysis" >> "$context_file"
            rg --color=never -l "$escaped_pkg" "$TARGET_DIR" -g "go.mod" 2>/dev/null | while read -r file; do
                echo "**File:** $file" >> "$context_file"
                echo '```go' >> "$context_file"
                rg --color=never -A2 -B2 "$escaped_pkg" "$file" 2>/dev/null >> "$context_file" 2>/dev/null
                echo '```' >> "$context_file"
            done
            ;;
            
        "maven")
            echo "## Maven-Specific Analysis" >> "$context_file"
            rg --color=never -l "$escaped_pkg" "$TARGET_DIR" -g "pom.xml" 2>/dev/null | while read -r file; do
                echo "**File:** $file" >> "$context_file"
                echo '```xml' >> "$context_file"
                rg --color=never -A5 -B5 "$escaped_pkg" "$file" 2>/dev/null >> "$context_file" 2>/dev/null
                echo '```' >> "$context_file"
            done
            ;;
    esac
    
    # Source analysis
    echo "## Source Analysis" >> "$context_file"
    echo "### Git URLs:" >> "$context_file"
    rg --color=never -A1 -B1 "git.*$escaped_pkg" "$TARGET_DIR" 2>/dev/null | head -20 >> "$context_file" 2>/dev/null
    
    echo "### Local Paths:" >> "$context_file"
    rg --color=never -A1 -B1 "file:.*$escaped_pkg\|path:.*$escaped_pkg\|\.\/.*$escaped_pkg" "$TARGET_DIR" 2>/dev/null | head -20 >> "$context_file" 2>/dev/null
    
    echo "### Private Registries:" >> "$context_file"
    rg --color=never -A1 -B1 "registry.*$escaped_pkg" "$TARGET_DIR" 2>/dev/null | head -20 >> "$context_file" 2>/dev/null
    
    echo "## Import/Usage Patterns" >> "$context_file"
    rg --color=never -A2 -B2 "import.*$escaped_pkg\|require.*$escaped_pkg\|from.*$escaped_pkg" "$TARGET_DIR" 2>/dev/null | head -30 >> "$context_file" 2>/dev/null
}

# LLM analysis with better error handling
analyze_with_gpt4o() {
    local package_name="$1"
    local package_type="$2"
    local context_file="$3"
    local output_file="$4"
    
    # Create directory if it doesn't exist
    mkdir -p "$(dirname "$output_file")"
    
    if [ ! -f "$context_file" ]; then
        err "Context file not found: $context_file"
        return 1
    fi
    
    local context_content
    context_content=$(cat "$context_file")
    
    # Smart prompt that lets the model reason based on context
    local prompt="Analyze this dependency confusion scenario based on the comprehensive codebase context provided.

## Package Information
- Name: $package_name
- Ecosystem: $package_type  
- Project Context: Full codebase analysis provided below

## Comprehensive Codebase Context
$context_content

## Analysis Task
Based on the actual codebase context above, determine if this package represents a real dependency confusion vulnerability.

Consider:
- How the package is actually used in the codebase
- Whether it's sourced from public registry vs private/git/local
- The project structure and dependency patterns
- Whether this appears to be an internal package or public dependency
- Any workspace, local path, or private registry configurations

Provide a thorough analysis based on the evidence found in the codebase context."

    local response
    response=$(curl -s -X POST "https://api.openai.com/v1/chat/completions" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $OPENAI_API_KEY" \
        -d "{
            \"model\": \"$MODEL\",
            \"messages\": [
                {
                    \"role\": \"system\", 
                    \"content\": \"You are a senior security engineer with deep expertise in dependency management and supply chain security. Analyze codebase context thoroughly and provide evidence-based assessments. Focus on actual usage patterns and sourcing methods found in the code.\"
                },
                {
                    \"role\": \"user\", 
                    \"content\": \"$prompt\"
                }
            ],
            \"response_format\": { \"type\": \"json_object\" },
            \"temperature\": 0.1,
            \"max_tokens\": 1500
        }" 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        err "API call failed for $package_name"
        return 1
    fi
    
    if [ -z "$response" ]; then
        err "Empty response for $package_name"
        return 1
    fi
    
    # Check for API errors
    local error_msg
    error_msg=$(echo "$response" | jq -r '.error.message // empty' 2>/dev/null)
    if [ -n "$error_msg" ]; then
        err "API error for $package_name: $error_msg"
        return 1
    fi
    
    local analysis
    analysis=$(echo "$response" | jq -r '.choices[0].message.content' 2>/dev/null)
    if [ -n "$analysis" ] && [ "$analysis" != "null" ]; then
        echo "$analysis" > "$output_file"
        return 0
    else
        err "Failed to extract analysis for $package_name"
        return 1
    fi
}

# Process all potential packages
process_potential_packages() {
    local dep_dir="$TARGET_DIR/DEP"
    
    if [ ! -d "$dep_dir" ]; then
        err "DEP directory not found: $dep_dir"
        err "Run the main scan script first to generate .potential files"
        exit 1
    fi
    
    local context_dir="$OUTPUT_DIR/contexts"
    local analysis_dir="$OUTPUT_DIR/analysis"
    local reports_dir="$OUTPUT_DIR/reports"
    
    mkdir -p "$context_dir" "$analysis_dir" "$reports_dir"
    
    local total_packages=0
    local processed=0
    local success_count=0
    local fail_count=0
    
    # Count total packages
    for potential_file in "$dep_dir"/*.potential; do
        if [ -f "$potential_file" ]; then
            local count
            count=$(wc -l < "$potential_file" 2>/dev/null || echo "0")
            total_packages=$((total_packages + count))
        fi
    done
    
    if [ "$total_packages" -eq 0 ]; then
        warn "No potential packages found in $dep_dir"
        return 1
    fi
    
    notice "Found $total_packages potential packages to analyze"
    
    # Process each potential file
    for potential_file in "$dep_dir"/*.potential; do
        if [ ! -f "$potential_file" ]; then
            continue
        fi
        
        local package_type
        package_type=$(basename "$potential_file" .potential)
        local package_count
        package_count=$(wc -l < "$potential_file" 2>/dev/null || echo "0")
        
        if [ "$package_count" -eq 0 ]; then
            continue
        fi
        
        notice "Processing $package_count $package_type packages..."
        
        while IFS= read -r package_name; do
            [ -z "$package_name" ] && continue
            
            processed=$((processed + 1))
            printf "[%d/%d] " "$processed" "$total_packages"
            notice "Analyzing: $package_name"
            
            # Sanitize package name for filename
            local safe_name
            safe_name=$(sanitize_filename "$package_name")
            
            # Extract deep context using ripgrep
            local context_file="$context_dir/${package_type}_${safe_name}.md"
            printf "    Extracting context..."
            if extract_deep_context "$package_name" "$package_type" "$context_file"; then
                printf "done\n"
            else
                printf "failed\n"
                fail_count=$((fail_count + 1))
                continue
            fi
            
            # Analyze with GPT-4o
            local analysis_file="$analysis_dir/${package_type}_${safe_name}.json"
            printf "    LLM analysis..."
            if analyze_with_gpt4o "$package_name" "$package_type" "$context_file" "$analysis_file"; then
                printf "done\n"
                success_count=$((success_count + 1))
            else
                printf "failed\n"
                fail_count=$((fail_count + 1))
            fi
            
            # Rate limiting
            sleep 3
            
        done < "$potential_file"
    done
    
    notice "Analysis completed: $success_count successful, $fail_count failed"
    return 0
}

# Generate intelligent report
generate_intelligent_report() {
    local analysis_dir="$OUTPUT_DIR/analysis"
    local report_file="$OUTPUT_DIR/dependency_triage_report_$(date +%Y%m%d_%H%M%S).md"
    
    notice "Generating intelligent triage report..."
    
    echo "# Dependency Confusion Triage Report" > "$report_file"
    echo "**Generated:** $(date)" >> "$report_file"
    echo "**Target:** $TARGET_DIR" >> "$report_file"
    echo "**Model:** $MODEL" >> "$report_file"
    echo "" >> "$report_file"
    
    local analyzed_count=0
    local vulnerable_count=0
    local false_positive_count=0
    local uncertain_count=0
    
    # Process all analysis files
    for analysis_file in "$analysis_dir"/*.json; do
        if [ ! -f "$analysis_file" ]; then
            continue
        fi
        
        analyzed_count=$((analyzed_count + 1))
        local filename
        filename=$(basename "$analysis_file" .json)
        local package_type
        package_type=$(echo "$filename" | sed 's/_.*$//')
        local package_name
        package_name=$(echo "$filename" | sed 's/^[^_]*_//')
        
        local analysis_content
        analysis_content=$(cat "$analysis_file")
        
        # Try to parse the JSON analysis
        local risk_level
        risk_level=$(echo "$analysis_content" | jq -r '.risk_level // .assessment // .vulnerability // "unknown"' 2>/dev/null || echo "unknown")
        
        # Basic classification based on content analysis
        if echo "$analysis_content" | grep -qi "vulnerable\|critical\|high.*risk\|dependency.*confusion"; then
            vulnerable_count=$((vulnerable_count + 1))
            echo "## 🔴 $package_name ($package_type)" >> "$report_file"
        elif echo "$analysis_content" | grep -qi "false.*positive\|not.*vulnerable\|safe\|workspace\|local.*path\|git.*url\|private.*registry"; then
            false_positive_count=$((false_positive_count + 1))
            echo "## ✅ $package_name ($package_type)" >> "$report_file"
        else
            uncertain_count=$((uncertain_count + 1))
            echo "## ⚠️  $package_name ($package_type)" >> "$report_file"
        fi
        
        echo '```json' >> "$report_file"
        if command -v jq >/dev/null 2>&1; then
            echo "$analysis_content" | jq '.' 2>/dev/null >> "$report_file" || echo "$analysis_content" >> "$report_file"
        else
            echo "$analysis_content" >> "$report_file"
        fi
        echo '```' >> "$report_file"
        echo "" >> "$report_file"
    done
    
    # Summary
    echo "# Executive Summary" >> "$report_file"
    echo "" >> "$report_file"
    echo "| Category | Count | Percentage |" >> "$report_file"
    echo "|----------|-------|------------|" >> "$report_file"
    
    if [ "$analyzed_count" -gt 0 ]; then
        local vulnerable_pct
        vulnerable_pct=$(echo "scale=1; $vulnerable_count * 100 / $analyzed_count" | bc 2>/dev/null || echo "0")
        local false_positive_pct
        false_positive_pct=$(echo "scale=1; $false_positive_count * 100 / $analyzed_count" | bc 2>/dev/null || echo "0")
        local uncertain_pct
        uncertain_pct=$(echo "scale=1; $uncertain_count * 100 / $analyzed_count" | bc 2>/dev/null || echo "0")
        
        echo "| 🔴 Potentially Vulnerable | $vulnerable_count | ${vulnerable_pct}% |" >> "$report_file"
        echo "| ✅ False Positives | $false_positive_count | ${false_positive_pct}% |" >> "$report_file"
        echo "| ⚠️  Uncertain/Manual Review | $uncertain_count | ${uncertain_pct}% |" >> "$report_file"
    else
        echo "| 🔴 Potentially Vulnerable | 0 | 0% |" >> "$report_file"
        echo "| ✅ False Positives | 0 | 0% |" >> "$report_file"
        echo "| ⚠️  Uncertain/Manual Review | 0 | 0% |" >> "$report_file"
    fi
    
    echo "| **Total Analyzed** | **$analyzed_count** | **100%** |" >> "$report_file"
    echo "" >> "$report_file"
    
    success "Comprehensive report generated: $report_file"
    
    # Terminal summary
    echo
    warn "=== TRIAGE SUMMARY ==="
    printf "🔴 Potentially Vulnerable: \e[1;31m%d\e[0m\n" "$vulnerable_count"
    printf "✅ False Positives: \e[1;32m%d\e[0m\n" "$false_positive_count" 
    printf "⚠️  Need Manual Review: \e[1;33m%d\e[0m\n" "$uncertain_count"
    printf "📊 Total Analyzed: \e[1;34m%d\e[0m\n" "$analyzed_count"
    echo
}

# Main execution
main() {
    notice "Starting advanced dependency triage with GPT-4o..."
    notice "Using ripgrep for deep context analysis..."
    
    if process_potential_packages; then
        generate_intelligent_report
        success "Advanced triage completed successfully!"
        notice "Full analysis available in: $OUTPUT_DIR"
        notice "Context files: $OUTPUT_DIR/contexts/"
        notice "LLM analysis: $OUTPUT_DIR/analysis/"
    else
        err "Triage process failed"
        exit 1
    fi
}

main "$@"
