#!/bin/bash

notice() { printf '\e[1;34m[INFO]\e[0m %s\n' "$*"; }
warn()   { printf '\e[1;33m[WARN]\e[0m %s\n' "$*"; }
err()    { printf '\e[1;31m[ERROR]\e[0m %s\n' "$*"; }

echo
echo -e "[ERROR] World \e[31mOFF\e[0m,Terminal \e[32mON \e[0m"
echo -e " █████                             █████           █████
░░███                             ░░███           ░░███
 ░███████  █████ ████  ███████  ███████   ██████  ███████    ██████  █████ █████  ██████
 ░███░░███░░███ ░███  ███░░███ ███░░███  ███░░███░░░███░    ███░░███░░███ ░░███  ███░░███
 ░███ ░███ ░███ ░███ ░███ ░███░███ ░███ ░███ ░███  ░███    ░███████  ░░░█████░  ░███████
 ░███ ░███ ░███ ░███ ░███ ░███░███ ░███ ░███ ░███  ░███ ███░███░░░    ███░░░███ ░███░░░
 ████████  ░░████████░░███████░░████████░░██████   ░░█████ ░░██████  █████ █████░░██████
░░░░░░░░    ░░░░░░░░  ░░░░░███ ░░░░░░░░  ░░░░░░     ░░░░░   ░░░░░░  ░░░░░ ░░░░░  ░░░░░░
                      ███ ░███
                     ░░██████
                      ░░░░░░                                                             "
echo -e "[WARN] Make \e[31mCritical\e[0m great again"

# ------------------------------
# Parse arguments
# ------------------------------
USER=""
ORG=""
FOLDER=""

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    -u|--user)
      USER=$2
      shift 2
      ;;
    -o|--org)
      ORG=$2
      shift 2
      ;;
    -f|--folder)
      FOLDER=$2
      shift 2
      ;;
    *)
      warn "Usage: bash scan.sh -u <USER> | -o <ORG> | -f <FOLDER>"
      exit 1
      ;;
  esac
done

# ------------------------------
# Validation
# ------------------------------
if [[ -z "$USER" && -z "$ORG" && -z "$FOLDER" ]]; then
  err "[-] You must specify a target with -u, -o, or -f"
  exit 1
fi

# ------------------------------
# Environment Setup
# ------------------------------
TARGET=${ORG:-${USER:-$(basename "$FOLDER")}}
OUTPUT="/tmp/${TARGET}"
mkdir -p "$OUTPUT"
echo "$TARGET" | anew githubTargets.txt

# ------------------------------
# Clone or Use Local Folder
# ------------------------------
cloneOrg() {
  notice "[-] Cloning GitHub Organization Repositories: $ORG"
  ghorg clone "$ORG" --fetch-all --quiet -p "$OUTPUT" -t "$GITHUB_TOKEN" \
    --color enabled --skip-archived #--skip-forks
}

cloneUser() {
  notice "[-] Cloning GitHub User Repositories: $USER"
  ghorg clone "$USER" --clone-type=user --fetch-all --quiet -p "$OUTPUT" -t "$GITHUB_TOKEN" \
    --color enabled --skip-archived --skip-forks
}

useLocalFolder() {
  notice "[-] Using local folder as source: $FOLDER"
}

# ------------------------------
# Dependency & Security Functions
# ------------------------------

gem-name() {
  local pkg=$1
  local code
  code=$(curl -Ls -o /dev/null -w "%{http_code}" "https://rubygems.org/gems/$pkg")
  if [ "$code" -eq 404 ]; then
    printf '\e[1;33m[WARN]\e[0m %s\n' "$pkg is available"
  fi
}

go-name() {
  local pkg=$1
  local code
  code=$(curl -Ls -o /dev/null -w "%{http_code}" "https://pkg.go.dev/$pkg")
  if [ "$code" -eq 404 ]; then
    printf '\e[1;33m[WARN]\e[0m %s\n' "$pkg is available"
  fi
}

maven-name() {
  local pkg=$1
  local code
  # Convert group:artifact to path
  local path=$(echo "$pkg" | tr '.' '/')
  code=$(curl -Ls -o /dev/null -w "%{http_code}" "https://repo1.maven.org/maven2/$path/")
  if [ "$code" -eq 404 ]; then
    printf '\e[1;33m[WARN]\e[0m %s\n' "$pkg is available"
  fi
}

docker-name() {
  local pkg=$1
  local code
  # Skip if it contains template variables or doesn't look like a real image name
  if [[ "$pkg" =~ \{\{.*\}\} ]] || [[ "$pkg" =~ \} ]] || [[ "$pkg" =~ ^[[:space:]]*$ ]] || [[ "$pkg" == *" "* ]]; then
    return 0
  fi
  code=$(curl -Ls -o /dev/null -w "%{http_code}" "https://hub.docker.com/v2/repositories/$pkg/")
  if [ "$code" -eq 404 ]; then
    printf '\e[1;33m[WARN]\e[0m %s\n' "$pkg is available"
  fi
}

rust-name() {
  local pkg=$1
  local code
  code=$(curl -Ls -o /dev/null -w "%{http_code}" "https://crates.io/api/v1/crates/$pkg")
  if [ "$code" -eq 404 ]; then
    printf '\e[1;33m[WARN]\e[0m %s\n' "$pkg is available"
  fi
}

broken-github() {
  local url=$1
  local code
  code=$(curl -Ls -o /dev/null -w "%{http_code}" "$url")
  if [ "$code" -eq 404 ]; then
    printf '\e[1;33m[WARN]\e[0m %s\n' "|-BROKEN-| $url => $code"
  fi
}

getDependencies() {
  mkdir -p "$OUTPUT/DEP"
  notice "Fetching NPM dependencies..."
  find "$OUTPUT" -name package.json | xargs -I {} get-dependencies {} | sort -u | anew "$OUTPUT/DEP/npm.deps"

  notice "Fetching Python dependencies..."
  find "$OUTPUT" -name "requirements*.txt" | \
    xargs -I {} awk '{print}' {} | grep -v "git:\|https\:\|http\:\|\#\|\""  | awk -F '=' '{print $1}' | awk -F ';' '{print $1}' | awk -F '(' '{print $1}' | awk -F '<' '{print $1}' | awk -F '>' '{print $1}' | awk -F '~' '{print $1}' | awk -F '[' '{print $1}' | awk NF | sed 's/ //g' | grep -v "^-" | sort | uniq | anew $OUTPUT/DEP/pip.deps

  notice "Fetching Ruby dependencies..."
  find "$OUTPUT" -name Gemfile | \
    xargs -I {} awk '{print}' {} | grep "^gem" | grep -v gemspec | sed "s/\"/\'/g" | awk -F "\'" '{print $2}' | awk NF | sort | uniq | anew "$OUTPUT/DEP/ruby.deps"

  notice "Fetching Go dependencies..."
  find "$OUTPUT" -name "go.mod" | \
    xargs -I {} awk '/^require \(/,/^\)/ {if (!/^require \(/ && !/^\)/) print $1}' {} | sort -u | anew "$OUTPUT/DEP/go.deps"
  
  find "$OUTPUT" -name "go.mod" | \
    xargs -I {} awk '/^require [^(]/ {print $2}' {} | sort -u | anew "$OUTPUT/DEP/go.deps"

  notice "Fetching Maven dependencies..."
  find "$OUTPUT" -name "pom.xml" | \
    xargs -I {} awk -F'[<>]' '/<groupId>[^<]+<\/groupId>/ {gid=$3} /<artifactId>[^<]+<\/artifactId>/ {print gid":"$3}' {} | sort -u | anew "$OUTPUT/DEP/maven.deps"

  notice "Fetching Docker dependencies..."
  # More precise Docker image extraction
  find "$OUTPUT" -name "Dockerfile" -o -name "docker-compose.yml" -o -name "docker-compose.yaml" -o -name "*.yaml" -o -name "*.yml" | \
    xargs -I {} grep -h "image:" {} | \
    awk '{print $2}' | \
    # Remove quotes and template variables
    sed 's/["'\'']//g' | \
    # Filter out Helm template syntax and invalid names
    grep -v "^{{" | \
    grep -v "}}$" | \
    grep -v "^\." | \
    grep -v "/.*/" | \
    # Basic validation - should look like docker image names
    grep -E "^[a-zA-Z0-9][a-zA-Z0-9_.-]*([/][a-zA-Z0-9][a-zA-Z0-9_.-]*)?(:[a-zA-Z0-9][a-zA-Z0-9_.-]*)?$" | \
    # Extract just the image name (before tag)
    cut -d: -f1 | \
    grep -v "^$" | sort -u | anew "$OUTPUT/DEP/docker.deps"

  notice "Fetching Rust dependencies..."
find "$OUTPUT" -name "Cargo.toml" | while read -r file; do
  awk -F'=' '
    /^\[dependencies\]/          { in_dep = 1; in_dev = 0; next }
    /^\[dev-dependencies\]/      { in_dev = 1; in_dep = 0; next }
    /^\[/                        { in_dep = 0; in_dev = 0 }  # other sections
    (in_dep || in_dev) && /^[a-zA-Z0-9_-]+\s*=/ {
      gsub(/[[:space:]]+/, "", $1)
      print $1
    }
  ' "$file"
done | sort -u | anew "$OUTPUT/DEP/rust.deps"

  }

checkDependencies() {
  export -f gem-name go-name maven-name docker-name rust-name
  notice "Checking npm..."
  cat "$OUTPUT/DEP/npm.deps" | xargs -I {} npm-name {} | anew "$OUTPUT/DEP/npm.checked"
  cat "$OUTPUT/DEP/npm.checked" | grep "is available" | cut -d ' ' -f2 | anew "$OUTPUT/DEP/npm.potential"

  notice "Checking pip..."
  cat "$OUTPUT/DEP/pip.deps" | xargs -I {} pip-name {} | anew "$OUTPUT/DEP/pip.checked"
  cat "$OUTPUT/DEP/pip.checked" | grep "is available" | awk '{print $1}' | anew "$OUTPUT/DEP/pip.potential"

  notice "Checking Ruby Gems..."
  cat "$OUTPUT/DEP/ruby.deps" | xargs -I {} bash -c 'gem-name "$@"' _ {} | \
    grep "is available" | cut -d ' ' -f2 | anew "$OUTPUT/DEP/gem.potential"

  notice "Checking Go modules..."
  cat "$OUTPUT/DEP/go.deps" | xargs -I {} bash -c 'go-name "$@"' _ {} | \
    grep "is available" | cut -d ' ' -f2 | anew "$OUTPUT/DEP/go.potential"

  notice "Checking Maven artifacts..."
  cat "$OUTPUT/DEP/maven.deps" | xargs -I {} bash -c 'maven-name "$@"' _ {} | \
    grep "is available" | cut -d ' ' -f2 | anew "$OUTPUT/DEP/maven.potential"

  notice "Checking Docker images..."
  # Filter out empty lines and invalid names before processing
  cat "$OUTPUT/DEP/docker.deps" | grep -v "^{{" | grep -v "^\." | grep -v "^[[:space:]]*$" | \
    xargs -I {} bash -c 'docker-name "$@"' _ {} | \
    grep "is available" | cut -d ' ' -f2 | anew "$OUTPUT/DEP/docker.potential"

  notice "Checking Rust crates..."
  cat "$OUTPUT/DEP/rust.deps" | xargs -I {} bash -c 'rust-name "$@"' _ {} | \
    grep "is available" | cut -d ' ' -f2 | anew "$OUTPUT/DEP/rust.potential"
}

brokenSupplychain() {
  export -f broken-github
  notice "[-] Finding broken GitHub references..."
  grep -roh -E "uses: [-a-zA-Z0-9\.]+/[-a-zA-Z0-9.]+@" "$OUTPUT" | \
    awk -F "/" '{print "https://github.com/"$1}' | sort -u | \
    xargs -I {} bash -c 'broken-github "$@"' _ {} | anew "$OUTPUT/DEP/github.potential"
}

secretFinding() {
  if [[ -n "$ORG" ]]; then
    trufflehog github --only-verified --token="$GITHUB_TOKEN" \
      --issue-comments --pr-comments --gist-comments --include-members \
      --archive-max-depth=50 --org="$ORG"
  elif [[ -n "$USER" ]]; then
    trufflehog filesystem --only-verified $OUTPUT
  fi
}

report() {
  warn "[+] Scan completed for $TARGET — results in $OUTPUT"
  
  # Show summary of potential findings
  echo
  notice "=== POTENTIAL FINDINGS SUMMARY ==="
  for dep_file in "$OUTPUT/DEP"/*.potential; do
    if [[ -f "$dep_file" ]]; then
      count=$(wc -l < "$dep_file" 2>/dev/null || echo "0")
      type=$(basename "$dep_file" .potential)
      if [[ "$count" -gt 0 ]]; then
        warn "$type: $count potential vulnerabilities"
      else
        notice "$type: $count potential vulnerabilities"
      fi
    fi
  done
}

# ------------------------------
# Main Execution
# ------------------------------
main() {
  if [[ -n "$ORG" ]]; then
    cloneOrg
  elif [[ -n "$USER" ]]; then
    cloneUser
  elif [[ -n "$FOLDER" ]]; then
    useLocalFolder
  fi

  node main.js "$OUTPUT" "$OUTPUT/extracted-npm.potential"

  getDependencies
  checkDependencies
  brokenSupplychain
  secretFinding
  report
}

main
