#!/usr/bin/env bash
# Dependency Confusion Scanner — Multi-Ecosystem Edition
# by Nyein Chan Aung (2025)

set -euo pipefail
IFS=$'\n\t'

#========================[ CONFIGURATION ]========================#
OUTPUT="./output"
mkdir -p "$OUTPUT/DEP"

# For colorized and consistent logs
notice() { printf "\e[1;34m[INFO]\e[0m %s\n" "$@"; }
warn()   { printf "\e[1;33m[WARN]\e[0m %s\n" "$@"; }
error()  { printf "\e[1;31m[ERR]\e[0m %s\n" "$@"; }

# Curl performance options
CURL_OPTS="-sL --connect-timeout 5 --max-time 10"

#========================[ NAME CHECKERS ]========================#

npm-name() {
  local pkg=$1
  local code
  code=$(curl $CURL_OPTS -o /dev/null -w "%{http_code}" "https://registry.npmjs.org/$pkg")
  if [ "$code" -eq 404 ]; then warn "$pkg is available"; fi
}

pip-name() {
  local pkg=$1
  local code
  code=$(curl $CURL_OPTS -o /dev/null -w "%{http_code}" "https://pypi.org/pypi/$pkg/json")
  if [ "$code" -eq 404 ]; then warn "$pkg is available"; fi
}

gem-name() {
  local pkg=$1
  local code
  code=$(curl $CURL_OPTS -o /dev/null -w "%{http_code}" "https://rubygems.org/api/v1/gems/$pkg.json")
  if [ "$code" -eq 404 ]; then warn "$pkg is available"; fi
}

go-name() {
  local pkg=$1
  local code
  code=$(curl $CURL_OPTS -o /dev/null -w "%{http_code}" "https://proxy.golang.org/${pkg}/@v/list")
  if [ "$code" -eq 404 ]; then warn "$pkg is available"; fi
}

maven-name() {
  local pkg=$1
  local group=$(echo "$pkg" | cut -d':' -f1 | tr '.' '/')
  local artifact=$(echo "$pkg" | cut -d':' -f2)
  local code
  code=$(curl $CURL_OPTS -o /dev/null -w "%{http_code}" "https://repo1.maven.org/maven2/${group}/${artifact}/")
  if [ "$code" -eq 404 ]; then warn "$pkg is available"; fi
}

docker-name() {
  local pkg=$1
  if [[ "$pkg" =~ \{\{.*\}\} ]] || [[ "$pkg" =~ \} ]] || [[ "$pkg" =~ ^[[:space:]]*$ ]] || [[ "$pkg" == *" "* ]]; then
    return 0
  fi

  local url="https://hub.docker.com/v2/repositories/$pkg/"
  if [[ "$pkg" != */* ]]; then
    url="https://hub.docker.com/v2/repositories/library/$pkg/"
  fi

  local code
  code=$(curl $CURL_OPTS -o /dev/null -w "%{http_code}" "$url")
  if [ "$code" -eq 404 ]; then warn "$pkg is available"; fi
}

rust-name() {
  local pkg=$1
  local code
  code=$(curl $CURL_OPTS -o /dev/null -w "%{http_code}" "https://crates.io/api/v1/crates/$pkg")
  if [ "$code" -eq 404 ]; then warn "$pkg is available"; fi
}

#========================[ DEP EXTRACTION ]========================#

getDependencies() {
  notice "Fetching NPM dependencies..."
  find "$OUTPUT" -name "package.json" | \
    xargs -I {} jq -r '.dependencies, .devDependencies | keys[]?' {} 2>/dev/null | \
    sort -u | anew "$OUTPUT/DEP/npm.deps"

  notice "Fetching Python dependencies..."
  find "$OUTPUT" -name "requirements.txt" | \
    xargs -I {} awk -F'[>=<]' '{gsub(/[[:space:]]/, "", $1); if ($1 != "") print $1}' {} | \
    sort -u | anew "$OUTPUT/DEP/pip.deps"

  notice "Fetching Ruby dependencies..."
  find "$OUTPUT" -name "Gemfile" | \
    xargs -I {} awk -F"'" '/^[[:space:]]*gem[[:space:]]*\(/ {print $2}' {} | \
    sort -u | anew "$OUTPUT/DEP/gem.deps"

  notice "Fetching Go dependencies..."
  find "$OUTPUT" -name "go.mod" | \
    xargs -I {} awk '/require\(/,/^\)/ {if ($1 !~ /^require|\)|$/) print $1} /^[[:alnum:]]/ {print $1}' {} | \
    sort -u | anew "$OUTPUT/DEP/go.deps"

  notice "Fetching Maven dependencies..."
  find "$OUTPUT" -name "pom.xml" | \
    xargs -I {} awk -F'[<>]' '/groupId|artifactId/ {printf "%s:", $3; getline; if ($1 ~ /artifactId/) printf "%s\n", $3}' {} | \
    sed 's/:$//' | sort -u | anew "$OUTPUT/DEP/maven.deps"

  notice "Fetching Docker dependencies..."
  find "$OUTPUT" -iname "Dockerfile" | \
    xargs -I {} grep -E "FROM|IMAGE" {} | \
    awk '{print $2}' | cut -d':' -f1 | sort -u | anew "$OUTPUT/DEP/docker.deps"

  notice "Fetching Rust dependencies..."
  find "$OUTPUT" -name "Cargo.toml" | \
    xargs -I {} awk -F '"' '
      /^\[dependencies\]/ {dep=1; next}
      /^\[dev-dependencies\]/ {dev=1; dep=0; next}
      /^\[/ {dep=0; dev=0}
      dep && /^[a-zA-Z0-9_-]+[[:space:]]*=/ {print $1}
      dev && /^[a-zA-Z0-9_-]+[[:space:]]*=/ {print $1}
    ' {} | sort -u | anew "$OUTPUT/DEP/rust.deps"
}

#========================[ DEP SCANNING ]========================#

scanDependencies() {
  notice "Checking NPM packages..."
  cat "$OUTPUT/DEP/npm.deps" | xargs -I {} bash -c 'npm-name "$@"' _ {} | grep "is available" | cut -d' ' -f2 | anew "$OUTPUT/DEP/npm.potential"

  notice "Checking Python packages..."
  cat "$OUTPUT/DEP/pip.deps" | xargs -I {} bash -c 'pip-name "$@"' _ {} | grep "is available" | cut -d' ' -f2 | anew "$OUTPUT/DEP/pip.potential"

  notice "Checking Ruby gems..."
  cat "$OUTPUT/DEP/gem.deps" | xargs -I {} bash -c 'gem-name "$@"' _ {} | grep "is available" | cut -d' ' -f2 | anew "$OUTPUT/DEP/gem.potential"

  notice "Checking Go modules..."
  cat "$OUTPUT/DEP/go.deps" | xargs -I {} bash -c 'go-name "$@"' _ {} | grep "is available" | cut -d' ' -f2 | anew "$OUTPUT/DEP/go.potential"

  notice "Checking Maven artifacts..."
  cat "$OUTPUT/DEP/maven.deps" | xargs -I {} bash -c 'maven-name "$@"' _ {} | grep "is available" | cut -d' ' -f2 | anew "$OUTPUT/DEP/maven.potential"

  notice "Checking Docker images..."
  cat "$OUTPUT/DEP/docker.deps" | xargs -I {} bash -c 'docker-name "$@"' _ {} | grep "is available" | cut -d' ' -f2 | anew "$OUTPUT/DEP/docker.potential"

  notice "Checking Rust crates..."
  cat "$OUTPUT/DEP/rust.deps" | xargs -I {} bash -c 'rust-name "$@"' _ {} | grep "is available" | cut -d' ' -f2 | anew "$OUTPUT/DEP/rust.potential"
}

#========================[ SUMMARY ]========================#

report() {
  echo
  notice "Summary of potential dependency confusion targets:"
  grep -r "is available" "$OUTPUT/DEP" | cut -d ':' -f1 | sort | uniq -c | sort -nr || true
}

#========================[ MAIN ]========================#

main() {
  getDependencies
  scanDependencies
  report
}

main "$@"
