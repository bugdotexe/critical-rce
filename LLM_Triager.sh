#!/usr/bin/env bash
# ==========================================================
#  AI-powered triage for Dependency Confusion scan results
#  Author: bugdotexe (triage automation)
# ==========================================================

set -e

notice() { printf '\e[1;34m[INFO]\e[0m %s\n' "$*"; }
warn()   { printf '\e[1;33m[WARN]\e[0m %s\n' "$*"; }
err()    { printf '\e[1;31m[ERROR]\e[0m %s\n' "$*"; }

OUTPUT=$1

if [[ -z "$OUTPUT" ]]; then
  err "Usage: bash ai_triage.sh <OUTPUT_FOLDER_FROM_SCAN>"
  exit 1
fi

# ----------------------------------------------------------
# Paths
# ----------------------------------------------------------
DEP_DIR="$OUTPUT/DEP"
if [[ ! -d "$DEP_DIR" ]]; then
  err "[-] $DEP_DIR not found — run your main scan first."
  exit 1
fi

notice "[+] Starting AI triage on dependency results at $DEP_DIR"
mkdir -p "$DEP_DIR/triage"

# ----------------------------------------------------------
# 1. Context extraction script
# ----------------------------------------------------------
cat > "$DEP_DIR/triage/context_extract.js" <<'EOF'
#!/usr/bin/env node
import fs from "fs";
import path from "path";
import glob from "glob";

const repoRoot = process.argv[2];
const depsFile = process.argv[3];
if (!repoRoot || !depsFile) {
  console.error("Usage: node context_extract.js <repo> <deps_file>");
  process.exit(1);
}

const deps = fs.readFileSync(depsFile, "utf-8").split("\n").filter(Boolean);
const output = [];

for (const dep of deps) {
  const matches = glob.sync(`${repoRoot}/**/*`, {
    nodir: true,
    ignore: ["**/node_modules/**", "**/.git/**", "**/venv/**"]
  });

  const usage = matches
    .filter(f => f.endsWith(".js") || f.endsWith(".ts") || f.endsWith(".json"))
    .slice(0, 400)
    .map(f => fs.readFileSync(f, "utf-8"))
    .filter(t => t.includes(dep))
    .slice(0, 3)
    .join("\n---\n");

  const npmrc = path.join(repoRoot, ".npmrc");
  const context = {
    package: dep,
    evidence: usage.slice(0, 2000) || "no evidence found",
    found_in_npmrc: fs.existsSync(npmrc),
    npmrc_content: fs.existsSync(npmrc)
      ? fs.readFileSync(npmrc, "utf-8").slice(0, 500)
      : ""
  };

  output.push(context);
}

fs.writeFileSync(depsFile + ".context.json", JSON.stringify(output, null, 2));
console.log(`[INFO] Extracted context for ${deps.length} packages`);
EOF
chmod +x "$DEP_DIR/triage/context_extract.js"

# ----------------------------------------------------------
# 2. LLM decision maker
# ----------------------------------------------------------
cat > "$DEP_DIR/triage/llm_decision.js" <<'EOF'
#!/usr/bin/env node
import fs from "fs";
import OpenAI from "openai";
const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

const contextFile = process.argv[2];
if (!contextFile) {
  console.error("Usage: node llm_decision.js <context.json>");
  process.exit(1);
}

const contexts = JSON.parse(fs.readFileSync(contextFile, "utf-8"));

async function triage(entry) {
  const prompt = `
You are a senior supply chain security analyst.
Given this context from a repository, decide whether the dependency seems like
a potential dependency confusion vulnerability or a false positive.

Respond strictly in JSON:
{
  "package": "${entry.package}",
  "decision": "potential_vulnerability" | "false_positive",
  "reason": "<short reason>"
}

Context:
${JSON.stringify(entry, null, 2)}
`;

  const res = await client.chat.completions.create({
    model: "gpt-5",
    messages: [{ role: "user", content: prompt }]
  });

  try {
    return JSON.parse(res.choices[0].message.content);
  } catch {
    return { package: entry.package, decision: "unknown", reason: "parse_error" };
  }
}

(async () => {
  const results = [];
  for (const e of contexts) results.push(await triage(e));
  fs.writeFileSync(contextFile.replace(".context.json", ".llm.json"), JSON.stringify(results, null, 2));
  console.log("[INFO] LLM triage completed for " + contexts.length + " packages");
})();
EOF
chmod +x "$DEP_DIR/triage/llm_decision.js"

# ----------------------------------------------------------
# 3. Run extraction + triage for each .potential file
# ----------------------------------------------------------
for f in "$DEP_DIR"/*.potential; do
  [[ -f "$f" ]] || continue
  notice "Processing $f"
  node "$DEP_DIR/triage/context_extract.js" "$OUTPUT" "$f"
  node "$DEP_DIR/triage/llm_decision.js" "$f.context.json"
done

# ----------------------------------------------------------
# 4. Summarize results
# ----------------------------------------------------------
notice "Summarizing triage results..."
jq -r '.[] | select(.decision=="potential_vulnerability") | .package' "$DEP_DIR"/*.llm.json \
  | sort -u > "$DEP_DIR/triage/final_potential.txt" || true

warn "[+] Triage complete. Confirmed potential vulnerabilities saved to:"
echo "    $DEP_DIR/triage/final_potential.txt"
