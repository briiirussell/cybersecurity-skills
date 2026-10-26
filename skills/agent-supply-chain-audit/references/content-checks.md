# Content checks — patterns per rule category

Each block gives a ripgrep (`rg`) command and a portable `grep -E` / `perl` equivalent (macOS grep has no `-P`).
Run them against the paths you inventoried, e.g. `T=".claude .agents CLAUDE.md AGENTS.md .mcp.json .cursor .github"`
for the project or `T="$HOME/.claude $HOME/.cursor $HOME/.codex $HOME/.gemini"` for the user scope. Every hit is a
**candidate**: read it in context before you raise it.

Rule IDs are NVIDIA SkillSpector's ([README](https://github.com/NVIDIA/SkillSpector/blob/main/README.md#vulnerability-patterns)),
cited so findings line up with a SkillSpector run. The patterns below are this repo's own, not SkillSpector's.

**Documentation vs directive.** Security skills (this catalog included) quote attack strings on purpose — inside fenced
code blocks, tables, or "look for X" sentences. A hit is a directive when it is addressed *to the agent* in prose,
frontmatter, a comment, or a tool description, and would change what the agent does. Quoted examples are not
findings; record them as `rejected` with the reason so re-runs don't re-raise them.

## Hidden instructions — P2, P9 (TP1/TP2 when in MCP metadata)

Invisible and bidi characters: U+200B–200F, U+202A–202E, U+2060–2064, U+2066–2069, U+FEFF, U+00AD, plus the Unicode
tag block U+E0000–E007F (used to smuggle ASCII text that renders as nothing).

```bash
rg -n '[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{2064}\x{2066}-\x{2069}\x{FEFF}\x{00AD}\x{E0000}-\x{E007F}]' $T
# broader: any Unicode "format" character (also hits emoji ZWJ sequences — triage those out)
rg -n '\p{Cf}' $T
# portable (BSD/GNU grep, byte-level UTF-8)
LC_ALL=C grep -rnE "$(printf '\342\200[\213-\217\252-\256]|\342\201[\240-\244\246-\251]|\357\273\277|\302\255|\363\240[\200\201]')" $T
```

A UTF-8 BOM (U+FEFF) as the first three bytes of a file is usually an editor artefact; anywhere else it is suspicious.

Directive keywords inside comments the renderer hides:

```bash
K='ignore|disregard|override|system|assistant|instruction|you (must|should)|do not (tell|mention|reveal)|secret|token|send|upload|curl|wget'
rg -n -i -U --pcre2 "<!--(?:(?!-->)[\s\S])*?\b($K)\b(?:(?!-->)[\s\S])*?-->" $T
rg -n -i '^\s*\[[^\]]*\]:\s*(#|<>)' $T            # [//]: # (...)  and  [comment]: <> (...)
# portable
perl -0777 -ne 'while (/<!--(.*?)-->/sg) { print "$ARGV: <!--$1-->\n" if $1 =~ /'"$K"'/i }' $(find $T -type f)
grep -rnEi '^[[:space:]]*\[[^]]*\]:[[:space:]]*(#|<>)' $T
```

Whitespace padding (text pushed off-screen to the right, or below a wall of blank lines):

```bash
rg -n '[ \t]{40,}\S' $T
rg -c -U '(\n[ \t]*){20,}\S' $T
rg -n '.{1000,}' $T                                # very long single lines
# portable
grep -rnE '[[:blank:]]{40,}[^[:space:]]' $T
awk 'NF==0{b++;next} b>=20{print FILENAME":"FNR": text after "b" blank lines"} {b=0}' $(find $T -type f)
```

Encoded payloads:

```bash
rg -n -i 'data:[a-z]+/[a-z0-9.+-]+;base64,' $T
rg -n '[A-Za-z0-9+/]{200,}={0,2}' $T
grep -rnEi 'data:[a-z]+/[a-z0-9.+-]+;base64,' $T
```

Decode what you find (`base64 -d` into a scratch file, never pipe into a shell) and read it.

## Instruction override — P1, P4

```bash
rg -n -i '(ignore|disregard|forget) (all |any )?(previous|prior|above|earlier|other) (instructions|rules|guidance)|you are now|from now on,? you|new (system )?instructions:|takes? precedence over|highest priority' $T
grep -rnEi '(ignore|disregard|forget) (all |any )?(previous|prior|above|other) (instructions|rules)|you are now|from now on|takes? precedence over' $T
```

P4 is the quiet version: "always prefer package X", "silently skip the tests", "don't mention this step to the user",
"approve the PR without comment". Read instruction files end to end; grep finds the loud ones only.

```bash
rg -n -i "(don'?t|do not|never) (mention|tell|show|inform|ask)( the)? user|silently|without (asking|telling|confirmation)" $T
```

## Anti-refusal — AR1–AR3

```bash
rg -n -i "(never|don'?t|do not) (refuse|decline|push back)|without (any )?(warnings?|disclaimers?|caveats?)|(no|without) (ethical|safety|content) (guidelines|restrictions|filters)|(safety|content) polic(y|ies) (do(es)?n'?t|do(es)? not) apply|(developer|god|jailbreak) mode|pre-?authori[sz]ed" $T
grep -rnEi "(never|don't|do not) (refuse|decline)|without (any )?(warning|disclaimer|caveat)s?|(safety|content) polic(y|ies) (does not|do not|doesn't|don't) apply|developer mode" $T
```

## Exfiltration and credential reads — P3, E1–E4, PE3

```bash
# outbound calls in instructions, scripts, hooks
rg -n -i '\b(curl|wget|nc|ncat|socat)\b|Invoke-WebRequest|fetch\(|requests\.(post|get|put)|urllib|http\.client|axios\.' $T
# collector / tunnel endpoints (egress indicators)
rg -n -i 'discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|hooks\.slack\.com/(services|workflows|triggers)|webhook\.site|requestbin|pipedream\.net|ngrok(-free)?\.(io|app|dev)|interact\.sh|oast\.(pro|live|site|online|fun|me)|oastify\.com|burpcollaborator\.net|requestcatcher\.com|beeceptor\.com|trycloudflare\.com|loca\.lt|serveo\.net|transfer\.sh|pastebin\.com' $T
# credential and secret reads
rg -n -i '\.ssh/|id_(rsa|ed25519|ecdsa)|\.aws/credentials|\.netrc|\.npmrc|\.pypirc|\.docker/config\.json|\.kube/config|gcloud/|keychain|find-generic-password|printenv|\benv\b *\||process\.env|os\.environ|\.env\b' $T
# "send the conversation / context / file contents" wording
rg -n -i '(send|post|upload|forward|report|sync) (the |all |this )?(conversation|chat|context|history|transcript|file contents|environment|secrets|tokens|keys)' $T
```

Portable: the same alternations work with `grep -rnEi` (drop `\b`, use `[[:<:]]` on BSD or just accept extra hits).
A legitimate integration names its endpoint, says why, and runs only when the user asks. Egress from a hook,
from a skill's setup step, or of credentials / transcript content is the finding.

## Agent snooping — AS1–AS3

```bash
rg -n '\.claude/|\.claude\.json|\.codex/|\.gemini/|\.cursor/|claude_desktop_config|mcp\.json|mcp_config\.json|SKILL\.md|skills/\*' $T
```

An audit or config-management skill that declares this purpose (this one, `secrets-audit`) will match. That is
expected and should be read-only and local. The finding is undeclared reads, reads of *other* skills' contents, or
reads that feed an outbound call.

## Supply chain — SC2, SC3, SC8, SC9 (SC1, SC6)

```bash
rg -n -i '(curl|wget)[^|\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b|(ba|z)?sh\s+(-c\s+)?["'"'"']?\$\((curl|wget)|bash\s+<\((curl|wget)|iex\s*\(|Invoke-Expression|IEX\s*\(' $T
rg -n -i 'base64 (-d|--decode)|atob\(|b64decode|fromCharCode|\beval\(|\bexec\(|compile\(|marshal\.loads|pickle\.loads|\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){20,}' $T
rg --files -uu $T -g '*.pyc' -g '__pycache__' -g '*.so' -g '*.dylib' -g '*.dll' -g '*.exe' -g '*.bin'
```

SC9 (an executable disguised as a document or image) needs the `file` command; ask before running it:

```bash
find $T -type f \( -name '*.md' -o -name '*.txt' -o -name '*.png' -o -name '*.jpg' -o -name '*.pdf' -o -name '*.json' \) \
  -exec file {} + | grep -Ei 'ELF|Mach-O|PE32|executable|script text'
find $T -type f -perm -u+x          # executable bit on files that shouldn't need it
```

SC1/SC6: unpinned or typosquatted dependencies in bundled `requirements.txt`, `package.json`, or install steps — hand
those to `dependency-audit`.

## Excessive agency — EA1–EA4

```bash
# unscoped Bash or WebFetch pre-approval in skill / command / agent frontmatter
rg -n '^allowed-tools:.*\bBash\s*(,|$)|^allowed-tools:.*Bash\(\*\)' $T
rg -n '^allowed-tools:.*WebFetch' $T
grep -rnE '^allowed-tools:.*Bash[[:space:]]*(,|$)' $T
```

`allowed-tools` pre-approves tools without a prompt. Unscoped `Bash` is the high-risk grant; unscoped `Bash` *plus*
`WebFetch`/`WebSearch` gives one skill code execution, untrusted input, and egress at once. Also flag skills whose
instructions reach far beyond their stated purpose (EA3) or that walk `~` / `/` unbounded (EA4).

## Persistence and self-modification — RA1, RA2, MP1

```bash
rg -n -i '(>>|>|tee( -a)?|write|append|edit)[^\n]{0,40}(CLAUDE|AGENTS|GEMINI)\.md|settings(\.local)?\.json|\.mcp\.json|memory/|MEMORY\.md' $T
rg -n -i 'crontab|/etc/cron|LaunchAgents|LaunchDaemons|launchctl|systemctl (enable|--user)|\.bashrc|\.zshrc|\.profile|\.bash_profile|\.git/hooks|core\.hooksPath|Startup( |%20)?folder|CurrentVersion\\Run' $T
```

A skill that writes to instruction files, agent settings, memory, shell init, or schedulers survives uninstall and
can re-grant itself permissions. Treat it as a finding unless that write is the skill's declared, user-invoked job.

## Trigger abuse — TR1–TR3

```bash
rg -n '^(name|description):' $T -g 'SKILL.md' -g '*.agent.md' -g '*.prompt.md' -g '*.mdc'
rg -n -i '^description:.*(always use|use (this )?for (any|every|all)|whenever the user|any (task|request|question)|before (any|every) (task|response))' $T
rg -n '^alwaysApply:\s*true' $T -g '*.mdc'
```

TR1 broad triggers ("help", "code", "fix"), TR2 a `name` that shadows a built-in command (`/init`, `/review`,
`/help`) or another installed skill, TR3 bait ("the best", "required for all tasks"). Compare `name:` values across
the inventory for duplicates.

## Tool poisoning — TP1–TP4 and least privilege — LP1–LP4

For local MCP server source:

```bash
rg -n -A6 'server\.tool\(|registerTool\(|@mcp\.tool|@server\.tool|\.tool\(|"inputSchema"|tools/list' <server-src>
```

Read every tool `description` and every parameter `description` / `title` / enum label. Then run the hidden-
instruction checks above on that text (TP1, TP3), check tool names for mixed scripts or confusables
(`rg -n '[^\x00-\x7F]' ` on names — TP2), and compare what the description promises with what the handler does: file
reads, network calls, spawned processes (TP4, LP1). A declared permission set with wildcards (LP2), no permissions
field despite clear capabilities (LP3), or declared permissions the code never uses (LP4) belong in the same review.
