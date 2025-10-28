#!/bin/bash

notice() { printf '\e[1;34m[INFO]\e[0m %s\n' "$*"; }
warn()   { printf '\e[1;33m[WARN]\e[0m %s\n' "$*"; }
err()    { printf '\e[1;31m[ERROR]\e[0m %s\n' "$*"; }

GITHUB_TOKEN=$GITHUB_TOKEN
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

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    -u|--user)
      USER=$2
      shift 2
      ;;
    -org|--org)
      ORG=$2
      shift 2
      ;;
    *)
      warn "[-] Usage: bash scan.sh -org <ORG>"
      exit 1
      ;;
  esac
done

if [[ -z "$ORG" ]];then
  warn "[-] Usage: bash scan.sh -org <ORG>"
  exit 1
fi

OUTPUT=/tmp/$ORG

cloneOrg() {
notice "[-] Cloning Github Repositories: $ORG "
ghorg clone $ORG --fetch-all --quiet -p $OUTPUT -t $GITHUB_TOKEN --color enabled  --skip-archived --skip-forks
}

gem-name() {
HTTP_CODE=404
response_code=$(curl --max-time 5 -Ls -o /dev/null -w "%{http_code}" https://rubygems.org/gems/$1)
if [ $response_code -eq $HTTP_CODE ]; then
    echo ""$1" is available"
else
    echo ""$1" is unavailable"
fi
}

getDependencies() {
mkdir -p $OUTPUT/DEP
notice "Fetching NPM dependencies : $ORG "
find $OUTPUT -name package.json | xargs -I {} get-dependencies {} | sort | uniq | anew $OUTPUT/DEP/npm.deps
###############
notice "Fetching PyPi dependencies : $ORG "
find $OUTPUT -name requirements.txt | xargs -I {} awk '{print}' {} | grep -v "git:\|https\:\|http\:\|\#\|\""  | awk -F '=' '{print $1}' | awk -F ';' '{print $1}' | awk -F '(' '{print $1}' | awk -F '<' '{print $1}' | awk -F '>' '{print $1}' | awk -F '~' '{print $1}' | awk -F '[' '{print $1}' | awk NF | sed 's/ //g' | grep -v "^-" | sort | uniq | anew $OUTPUT/DEP/pip.deps
find $OUTPUT -name requirements-dev.txt | xargs -I {} awk '{print}' {} | grep -v "git:\|https\:\|http\:\|\#\|\""  | awk -F '=' '{print $1}' | awk -F ';' '{print $1}' | awk -F '(' '{print $1}' | awk -F '<' '{print $1}' | awk -F '>' '{print $1}' | awk -F '~' '{print $1}' | awk -F '[' '{print $1}' | awk NF | sed 's/ //g' | grep -v "^-" | sort | uniq | anew $OUTPUT/DEP/pip.deps
###############
notice "Fetching Ruby dependencies : $ORG "
find $OUTPUT -name Gemfile | xargs -I {} awk '{print}' {} | grep "^gem" | grep -v gemspec | sed "s/\"/\'/g" | awk -F "\'" '{print $2}' | awk NF | sort | uniq | anew $OUTPUT/DEP/ruby.deps
}

checkDependencies() {

export -f gem-name

notice "[-] Checking npm dependencies: $ORG "
cat "$OUTPUT/DEP/npm.deps" | xargs -I {} npm-name {} | anew $OUTPUT/DEP/npm.checked
cat $OUTPUT/DEP/npm.checked | grep "is available" | cut -d ' ' -f2 | anew $OUTPUT/DEP/npm.potential

notice "[-] Checking pypi dependencies: $ORG "
cat "$OUTPUT/DEP/pip.deps" | sed 's/[[:space:]]//g' | awk '{print $1}' | xargs -I {} pip-name {} | anew $OUTPUT/DEP/pip.checked
cat $OUTPUT/DEP/pip.checked | grep "is available" | cut -d ' ' -f2 | anew $OUTPUT/DEP/pip.potential

notice "[-] Checking ruby Gem dependencies: $ORG "
cat "$OUTPUT/DEP/ruby.deps" | xargs -I {} bash -c 'gem-name "$@"' _ {} | grep "is available" | cut -d ' ' -f1 | anew $OUTPUT/DEP/gem.potential
}

report() {
warn "[+]Scan results summary report: "
}

main() {
cloneOrg
#############
node main.js $OUTPUT
cp available-packages.txt "$ORG.available-packages.txt"
#############
getDependencies
#############
checkDependencies
#############
report
}

main
