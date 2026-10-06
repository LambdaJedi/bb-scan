<#
.SYNOPSIS
  bb-scan v3.5: source-code audit pipeline for bug bounty (repo-type aware).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RepoUrl,
    [string]$WorkDir = "repos",
    [string]$ReportDir = "reports",
    [string]$FastModel = "qwen2.5-coder:3b",
    [string]$DeepModel = "qwen2.5-coder:7b",
    [string[]]$SemgrepConfigs = @("p/security-audit", "p/owasp-top-ten", "p/secrets", "p/command-injection", "p/c", "p/cpp", "p/rust"),
    [string[]]$ExcludePaths = @("node_modules", "test", "tests", "__tests__", "fixtures", "benchmarks", "evals",
        "examples", "docs", "e2e", "*.min.js", "*.spec.*", "*.test.*"),
    [string[]]$IncludePaths = @(),
    [int]$NumCtx = 4096,
    [int]$MaxLeads = 60,
    [int]$MaxPerGroup = 2,
    [int]$MaxSurfaceLeads = 20,
    [int]$SecondOpinionCount = 8,
    [ValidateSet("auto", "service", "library", "cli_desktop", "infra", "vscode_extension")][string]$RepoType = "auto",
    [int]$MaxLocalLeads = 25,
    [switch]$UseFastFilter,
    [switch]$SkipSurfaceMap,
    [switch]$ForceSurface,
    [switch]$ForceLocalChecks,
    [switch]$SurfaceInSdk,
    [switch]$NoAutoLanguageRules,
    [switch]$NoAutoResolve,
    [switch]$NoRuleCaps,
    [switch]$DisableSuppressions,
    [switch]$UseCodeQL,
    [ValidateSet("auto", "javascript", "python", "java", "csharp", "go", "ruby", "cpp")][string]$CodeQLLanguage = "auto",
    [ValidateSet("security-extended", "security-and-quality")][string]$CodeQLSuite = "security-extended",
    [int]$MaxCodeQLLeads = 25,
    [switch]$SkipDockerDetect
)

$ErrorActionPreference = "Stop"
$env:PYTHONUTF8 = "1"
$ScriptVersion = "bb-scan v3.5"
$OllamaUrl = "http://localhost:11434"
$CacheVersion = "v3.5"
$AllowedVerdicts = @("interesting", "suspicious", "potential_vuln", "not_vuln")
$script:RouteCount = 0
$script:RepoTypeName = "service"
$script:RepoRoot = ""
$script:AttackerOptions = "remote_unauthenticated|remote_authenticated|untrusted_content|local_only|none"
$script:AttackerList = @("remote_unauthenticated", "remote_authenticated", "untrusted_content", "local_only", "none")
$script:Outside = @("remote_unauthenticated", "remote_authenticated", "untrusted_content")
$script:AttackerGuidance = "This is a network service or web app."
$script:RuleCaps = @{}
$RouteRx = '\b(app|router|server|api)\.(get|post|put|patch|delete|all)\s*\(|export\s+(async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b|@(Get|Post|Put|Patch|Delete|Request)Mapping\b|@(app|bp|router)\.(route|get|post|put|patch|delete)\(|Route::(get|post|put|patch|delete|any)|\bHandleFunc\('
$ServerDepRx = '(?i)(["'']\s*(express|fastify|koa|hono|next|nuxt|@nestjs/core)\s*["'']\s*:)|\b(flask|django|fastapi|starlette|aiohttp|tornado|spring-boot-starter-web|sinatra|laravel/framework|gin-gonic/gin|labstack/echo|gofiber/fiber)\b|gem\s+["'']rails["'']'
$PrivRx = '(?i)\b(sudo|pkexec|doas)\b|setuid|polkit|User=root|/etc/sudoers'

$TagRules = @(
    @{ Tag = "ci";        Rx = '(^|/)\.github/(workflows|actions)/' },
    @{ Tag = "test";      Rx = '(^|/)(tests?|__tests__|specs?|e2e|fixtures?|__mocks__|mocks?)(/|$)|\.(test|spec)\.[a-z0-9]+$|(^|/)test-[^/]+$|[-_]test\.[a-z0-9]+$' },
    @{ Tag = "docs";      Rx = '(^|/)(docs?|documentation|website|blog)(/|$)|\.mdx?$' },
    @{ Tag = "generated"; Rx = '(^|/)(dist|generated|vendor|coverage|\.next|\.turbo|out)(/|$)|\.min\.js$|\.generated\.' },
    @{ Tag = "demo";      Rx = '(^|/)(workbench|examples?|demos?|samples?|playground|templates?|sandbox)(/|$)|-playground(/|$)' },
    @{ Tag = "build";     Rx = '(^|/)(scripts|tools|tooling|\.husky)(/|$)|(^|/)(build|gulpfile|webpack\.config|rollup\.config|vite\.config|esbuild)[^/]*\.(js|mjs|cjs|ts)$' },
    @{ Tag = "sdk";       Rx = '(^|/)packages/(core|sdk|runtime|client|utils|world[^/]*)(/|$)|(^|/)sdk(/|$)' },
    @{ Tag = "web";       Rx = '(^|/)(packages/web|apps?|server|api|backend|frontend|site)(/|$)' },
    @{ Tag = "angular";   Rx = '(?i)\.component\.html$' }
)

$CiHygieneRx = 'mutable-action-tag|not-pinned|pinned-to-commit|secrets-inherit|minimum-release-age|npm-missing'
$ReachableTriggers = @("pull_request", "pull_request_target", "issue_comment", "issues", "workflow_run",
    "discussion", "discussion_comment", "pull_request_review", "pull_request_review_comment", "fork")

$FixturePathRx = '(?i)(^|/)(tests?|specs?|fixtures?|mocks?|__mocks__|acceptance|testdata|samples?|examples?)(/|$)'
$EscapeHelperRx = 'escapeHtml|escape_html|htmlEscape|sanitize|DOMPurify|\bxss\b|encodeURIComponent'

$CiSafeContexts = @(
    'github.sha', 'github.run_id', 'github.run_number', 'github.run_attempt',
    'github.actor', 'github.event_name', 'github.event.pull_request.base.sha',
    'github.event.before', 'github.event.created', 'github.server_url',
    'github.repository', 'github.workspace', 'github.token'
)

$LoggerCredRuleRx = 'logger-credential|log-credential|credential-leak|password-log|token-log|secret-log'
$CredNameRx = '\b(password|passwd|token|secret|api[_-]?key|apikey|authorization|auth[_-]?token|access[_-]?token|private[_-]?key|client[_-]?secret)\b'

$Playbooks = @(
    @{ Match = '^codeql-'; Flow = $true; Ask = "CodeQL has already traced a dataflow path from a source to a sink (see Dataflow path in the hint -- trust those steps as real). Decide: is the source reachable by an outside attacker for this repo type, and does any step on the path sanitize, encode, parameterize, escape or otherwise neutralize the value before the sink? If so, verdict is not_vuln. Quote the source line and the sink line, copied exactly from the dataflow path or the code below." },
    @{ Match = 'ext-webview-html'; Flow = $true; Ask = "This code builds or injects HTML or script for a webview or page from variables. Where does the data come from: the remote service (issue, merge request, markdown, file contents, logs), the opened workspace, or only the extension's own constants? Is it escaped, sanitized or nonce-gated, and is there a strict content security policy? Quote where the data enters and the line that injects it. A nonce or a static value is not a vulnerability." },
    @{ Match = 'ext-enable-scripts'; Flow = $false; Ask = "This webview has scripts enabled. Does the page it loads include data from the remote service or the workspace? Is there a content security policy with a nonce and a restrictive default? Enabling scripts alone is not a vulnerability. Quote the options and the policy if you can see it." },
    @{ Match = 'ext-postmessage'; Flow = $false; Ask = "This handler receives messages between a webview and the extension. Can an outsider influence the message content (it may come from remote content rendered in the webview)? Is the message type and payload validated before it triggers a command, a file operation, a URL open or a token use? Quote the handler line." },
    @{ Match = 'ext-open-external'; Flow = $true; Ask = "This code opens a link or URI. Can remote content or workspace data choose the URI? Are the scheme (https only, no file or command URIs) and the host checked? Quote where the URI is built and the open call." },
    @{ Match = 'ext-exec'; Flow = $true; Ask = "This code starts a process. Can its command or arguments come from workspace configuration, remote data or file names that an outsider controls (for example a malicious repository the user opens)? Quote where the value is set and the process call." },
    @{ Match = 'ext-uri-handler'; Flow = $false; Ask = "This registers a handler for links that external pages can trigger. Does it validate the path and query before acting, and what actions can it reach? Quote the handler." },
    @{ Match = 'ext-token-log'; Flow = $false; Ask = "This line may write a credential to a log or output channel. Is the logged value the actual secret, or only a name or a flag? Quote the line." },
    @{ Match = 'local-priv-exec'; Flow = $true; Ask = "This script runs a command with elevated privileges (sudo, pkexec, doas) and puts a variable in it. Where does the variable's value come from (command-line argument, environment, a file, downloaded data, user input)? Can a less-privileged local user or untrusted content control it, and does the elevated command treat it as a path, a command or an option? Quote the line that assigns the variable and the elevated line. A script that only installs what the user asked for is not a vulnerability." },
    @{ Match = 'local-pipe-shell'; Flow = $false; Ask = "This line downloads code and pipes it to a shell. Is the URL fixed and served over HTTPS from the project's own domain, or can an outsider influence it? Does it run as root? Quote the line." },
    @{ Match = 'local-tmp'; Flow = $false; Ask = "This script uses a fixed path in the shared temporary directory. Could another local user pre-create or replace that path (symlink or race) to read or overwrite data the script handles, especially when it runs as root or handles secrets? Quote the line and say what the script reads or writes there." },
    @{ Match = 'local-chmod'; Flow = $false; Ask = "This line makes a file or directory writable by others. Is it a sensitive file (credentials, an executable, a config used by a privileged process) or a harmless runtime path? Quote the line." },
    @{ Match = 'local-eval'; Flow = $true; Ask = "This script evaluates a string that contains a variable. Where does the variable's value come from, and can an outside attacker or a less-privileged user influence it? Quote where it is assigned and the eval line." },
    @{ Match = 'urllib|requests|http-client|insecure-request'; Flow = $true; Ask = "Is the URL, host or header value influenced by an outside attacker, or is this a client calling a fixed endpoint with its own configured credentials (not a vulnerability)? Is the fetched data later trusted unsafely (executed, extracted, parsed with an unsafe parser, written to a path the attacker chooses)? Quote the lines." },
    @{ Match = 'code-checkout|target-code'; Flow = $false; Ask = "This workflow runs on a trigger that outsiders can cause. Does it check out and then build, install or run code from the pull request or fork (head ref or sha) while it has secrets or write permissions? Quote the checkout step and the step that runs the code." },
    @{ Match = 'shell-injection|script-injection|expression-injection'; Flow = $true; Ask = "Is an attacker-controlled GitHub context value (pull request title, body, head ref, comment body, issue title) interpolated into a run script? Quote the exact interpolation. Values such as github.sha, github.run_id, github.run_number, github.run_attempt, github.actor, github.event_name, github.event.pull_request.base.sha, github.event.before, github.event.created, github.server_url, github.repository, github.workspace, and github.token are NOT attacker-controlled text and do not count. If every interpolation in the run block is from that list, the verdict is not_vuln." },
    @{ Match = 'md5|sha1|weak-hash|insecure-hash|hashlib|crypto'; Flow = $false; Ask = "Find what this digest or cipher protects. Is it used for passwords, signatures, tokens, integrity checks or authorization decisions (security use), or only for cache keys, ids or non-security checksums (not a vulnerability)? Show the call site." },
    @{ Match = 'secret|credential|api-key|apikey|password|private-key|token'; Flow = $false; Ask = "Is this a real, live credential or only a placeholder, test value or example? Where is it used and what would it grant?" },
    @{ Match = 'sql|sqli|nosql'; Flow = $true; Ask = "Is attacker-controlled input concatenated into the query instead of being parameterized?" },
    @{ Match = 'xss|innerhtml|dangerously|template-injection|html|script-tag'; Flow = $true; Ask = "Does attacker-controlled data reach HTML, DOM or a template without encoding?" },
    @{ Match = 'deserial|pickle|yaml|eval|vm\.|unsafe-load'; Flow = $true; Ask = "Can attacker-controlled data reach this deserialization, eval or dynamic code path? If the call is guarded by an HMAC verification, signature check, or constant-time comparison in the preceding lines, say so and use verdict not_vuln." },
    @{ Match = 'traversal|path-join|file-inclusion|readfile|zip-slip|sendfile'; Flow = $true; Ask = "Can an attacker control the file path and escape the intended directory?" },
    @{ Match = 'ssrf|fetch|http-request|open-redirect|redirect'; Flow = $true; Ask = "Can an attacker choose the URL, host or redirect target? Are internal addresses or other origins blocked?" },
    @{ Match = 'jwt|auth|cors|csrf|cookie|session'; Flow = $true; Ask = "Does this weaken authentication, session handling or cross-origin protection in a way an outside attacker can exploit?" },
    @{ Match = 'child-process|command-injection|exec|spawn|shell|subprocess'; Flow = $true; Ask = "Can an attacker who is NOT already running code on this machine influence the command, its arguments or the shell string? Name the attacker and the entry point. Local config, developer-run CLI flags and build scripts do not count." }
)

$StopWords = @("const", "let", "var", "return", "function", "async", "await", "this", "null", "true", "false", "new",
    "string", "number", "import", "export", "from", "public", "private", "protected", "static", "void", "class",
    "final", "else", "for", "while", "try", "catch", "throw", "typeof", "undefined", "req", "res", "request",
    "response", "args")

$LangRules = @{
    ".java" = "p/java"; ".py" = "p/python"; ".js" = "p/javascript"; ".mjs" = "p/javascript"
    ".ts" = "p/typescript"; ".tsx" = "p/typescript"; ".php" = "p/php"; ".go" = "p/golang"; ".rb" = "p/ruby"
    ".c" = "p/c"; ".h" = "p/c"; ".cpp" = "p/cpp"; ".cc" = "p/cpp"; ".hpp" = "p/cpp"; ".rs" = "p/rust"
}

function Write-Step([string]$Message) { Write-Host "==> $Message" -ForegroundColor Cyan }
function Normalize-Text([string]$Text) { if ($null -eq $Text) { return "" }; return ([regex]::Replace($Text, "\s+", " ")).Trim() }
function Remove-LinePrefix([string]$Text) { if ($null -eq $Text) { return "" }; return (($Text -split "`n" | ForEach-Object { $_ -replace '(?m)^\s*\d+:\s?', '' }) -join " ") }
function Get-Sha([string]$Text) { $sha = [System.Security.Cryptography.SHA256]::Create(); $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text); return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join "") }
function Join-Field($Value) { if ($null -eq $Value) { return "" }; if ($Value -is [System.Array]) { return (($Value | ForEach-Object { [string]$_ }) -join "; ") }; return [string]$Value }
function Get-Weight($Table, [string]$Key, [double]$Default) { if ($Table.ContainsKey($Key)) { return [double]$Table[$Key] }; return $Default }

function Get-Tags([string]$RelPath) {
    $tags = New-Object System.Collections.Generic.List[string]
    foreach ($rule in $TagRules) {
        if ($rule.Tag -eq "build" -and $script:RepoTypeName -eq "cli_desktop") { continue }
        if ($RelPath -match $rule.Rx) { $tags.Add($rule.Tag) }
    }
    if ($tags.Count -eq 0) { $tags.Add("other") }
    return @($tags)
}

function Get-RelPath([string]$FullPath, [string]$Root) {
    if ($FullPath.StartsWith($Root, [System.StringComparison]::OrdinalIgnoreCase)) {
        return (($FullPath.Substring($Root.Length)).TrimStart('\', '/') -replace '\\', '/')
    }
    return ($FullPath -replace '\\', '/')
}

function Get-Identifiers([string]$Text) {
    $set = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($m in [regex]::Matches($Text, '[A-Za-z_][A-Za-z0-9_]{2,}')) {
        $w = $m.Value
        if ($StopWords -notcontains $w.ToLower()) { [void]$set.Add($w) }
    }
    return , $set
}

function Test-Overlap($A, $B) { foreach ($x in $A) { if ($B.Contains($x)) { return $true } }; return $false }

function Test-QuoteFound([string]$Quote, [string]$Hay) {
    if ([string]::IsNullOrWhiteSpace($Quote)) { return $false }
    $clean = Remove-LinePrefix $Quote
    $pieces = @($clean -split '\.\.\.' | ForEach-Object { Normalize-Text $_ } | Where-Object { $_.Length -ge 15 })
    if ($pieces.Count -eq 0) { return $false }
    foreach ($p in $pieces) { if (-not $Hay.Contains($p)) { return $false } }
    return $true
}

function Invoke-Llm([string]$Model, [string]$Prompt) {
    $body = @{
        model      = $Model; stream = $false; format = "json"; keep_alive = "2m"
        options    = @{ temperature = 0.1; num_ctx = $NumCtx }
        messages   = @(@{ role = "user"; content = $Prompt })
    } | ConvertTo-Json -Depth 6
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
    for ($try = 1; $try -le 2; $try++) {
        $resp = Invoke-RestMethod -Uri "$OllamaUrl/api/chat" -Method Post -Body $bytes -ContentType "application/json; charset=utf-8" -TimeoutSec 900
        try { return ($resp.message.content | ConvertFrom-Json) } catch { }
    }
    return $null
}

function Test-Ollama {
    try { $tags = Invoke-RestMethod -Uri "$OllamaUrl/api/tags" -TimeoutSec 10 }
    catch { throw "Ollama is not reachable at $OllamaUrl. Start the Ollama app first." }
    $names = @($tags.models | ForEach-Object { $_.name })
    $needed = @($DeepModel)
    if ($UseFastFilter) { $needed += $FastModel }
    foreach ($m in $needed) { if ($names -notcontains $m) { throw "Model '$m' not found. Run: ollama pull $m" } }
}

function Get-SemgrepVersion {
    try {
        if (Get-Command semgrep -ErrorAction SilentlyContinue) { return [string](@(& semgrep --version 2>&1)[0]) }
        return [string](@(& python -m semgrep --version 2>&1)[0])
    } catch { return "unknown" }
}

function Invoke-SemgrepConfig([string]$Config, [string]$Target, [string]$OutFile) {
    if (Test-Path $OutFile) { Remove-Item $OutFile -Force }
    $semArgs = @("--config", $Config, "--metrics=off", "--json", "--output", $OutFile)
    foreach ($e in $ExcludePaths) { $semArgs += @("--exclude", $e) }
    foreach ($i in $IncludePaths) { $semArgs += @("--include", $i) }
    $semArgs += $Target
    $old = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $semOut = @()
    if (Get-Command semgrep -ErrorAction SilentlyContinue) { $semOut = & semgrep @semArgs 2>&1 }
    else { $semOut = & python -m semgrep @semArgs 2>&1 }
    $ErrorActionPreference = $old
    $exists = Test-Path $OutFile
    if (-not $exists -and $semOut) {
        $firstLines = ($semOut | Select-Object -First 3) -join ' | '
        Write-Warning ("Semgrep [$Config] produced no output: $firstLines")
    }
    return $exists
}

function Get-Context([string[]]$Lines, [int]$Start, [int]$End) {
    $pad = 20
    $top = [Math]::Max(0, $Start - 1 - $pad)
    $name = ""
    $sigLine = ""
    $sig = '^\s*((public|private|protected|static|async)\s+.*\(|def\s+\w+\s*\(|function\s+\w+\s*\(|(const|let)\s+\w+\s*=\s*(async\s*)?\()'
    $skip = '^\s*(if|for|while|switch|catch|else|return)\b'
    for ($i = $Start - 1; $i -ge $top; $i--) {
        if ($i -ge $Lines.Count) { continue }
        if ($Lines[$i] -match $sig -and $Lines[$i] -notmatch $skip) {
            $top = $i; $sigLine = $Lines[$i]
            if ($Lines[$i] -match '(\w+)\s*\(') { $name = $Matches[1] }
            break
        }
    }
    $bottom = [Math]::Min($Lines.Count, $End + $pad)
    $buf = New-Object System.Collections.Generic.List[string]
    for ($n = $top; $n -lt $bottom; $n++) { $row = "{0}: {1}" -f ($n + 1), $Lines[$n]; $buf.Add($row) }
    $snippet = $buf -join "`n"
    if ($snippet.Length -gt 3500) { $snippet = $snippet.Substring(0, 3500) }
    return [pscustomobject]@{ Snippet = $snippet; Name = $name; Sig = $sigLine }
}

function Get-Callers([string]$Repo, [string]$Name, [string]$OwnFile, [string]$ExcludeRegex, [int]$Limit) {
    if (-not $Name) { return @() }
    $hits = Get-ChildItem -Path $Repo -Recurse -File -Include *.java, *.py, *.js, *.mjs, *.ts, *.tsx, *.php, *.rb, *.go, *.cs, *.c, *.h, *.cpp, *.cc, *.hpp, *.rs -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -ne $OwnFile -and $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch $ExcludeRegex } |
        Select-String -SimpleMatch ($Name + "(") -ErrorAction SilentlyContinue | Select-Object -First $Limit
    return @($hits | ForEach-Object { "{0}:{1}: {2}" -f $_.Path, $_.LineNumber, $_.Line.Trim() })
}


function Get-Assignment([string]$Repo, [string]$Name, [string]$ExcludeRegex, [int]$Limit = 3) {
    if (-not $Name -or $Name.Length -lt 3) { return @() }
    $escaped = [regex]::Escape($Name)
    $pat = '(?m)(\bconst\b|\blet\b|\bvar\b)\s*\{[^}]*\b' + $escaped + '\b[^}]*\}\s*=|' +
           '(?m)(\bconst\b|\blet\b|\bvar\b)\s+' + $escaped + '\s*[:=]|' +
           '(?m)\b' + $escaped + '\s*[:=]\s*req\.(query|params|body|session)\b'
    $hits = Get-ChildItem -Path $Repo -Recurse -File -Include *.ts, *.tsx, *.js, *.mjs, *.py, *.go, *.rb, *.java -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch $ExcludeRegex } |
        Select-String -Pattern $pat -ErrorAction SilentlyContinue | Select-Object -First $Limit
    $out = @()
    foreach ($h in $hits) {
        $lines = @(Get-Content -LiteralPath $h.Path -Encoding UTF8)
        $start = [Math]::Max(0, $h.LineNumber - 1 - 3)
        $end = [Math]::Min($lines.Count - 1, $h.LineNumber - 1 + 8)
        if ($start -gt $end) { continue }
        $body = ($lines[$start..$end]) -join "`n"
        if ($body.Length -gt 1200) { $body = $body.Substring(0, 1200) }
        $out += ("// assignment of '{0}' -- {1}:{2}" -f $Name, $h.Path, $h.LineNumber) + "`n" + $body
    }
    return $out
}


$EnglishStopWords = @("the", "a", "an", "of", "in", "on", "at", "to", "for", "and", "or", "is", "are",
    "was", "were", "be", "been", "this", "that", "these", "those", "what", "where", "when", "how",
    "why", "which", "who", "does", "do", "did", "implementation", "function", "method", "value",
    "variable", "parameter", "definition", "behind", "check", "see", "its", "it", "whether",
    "code", "line", "lines", "file", "called", "call", "source", "sink", "data", "would", "could",
    "need", "needed", "unknown", "unclear", "logic", "handler", "handling", "referenced", "class")

function Get-MissingContextCandidates([string]$Text, [string]$Hay, [int]$Max = 3) {
    if (-not $Text) { return @() }
    $tokens = [regex]::Matches($Text, '[A-Za-z_][A-Za-z0-9_]{2,}') | ForEach-Object { $_.Value } | Select-Object -Unique
    $scored = @()
    foreach ($t in $tokens) {
        if ($EnglishStopWords -contains $t.ToLower()) { continue }
        $isCodeShaped = ($t -cmatch '[a-z][A-Z]') -or ($t -cmatch '[A-Z][a-z].*[A-Z]') -or ($t -match '_')
        $seenInCode = $Hay -and (Normalize-Text $t) -and $Hay.Contains($t)
        if (-not $isCodeShaped -and -not $seenInCode) { continue }
        $score = 0
        if ($isCodeShaped) { $score += 2 }
        if ($seenInCode) { $score += 1 }
        $scored += [pscustomobject]@{ Name = $t; Score = $score }
    }
    return @($scored | Sort-Object Score -Descending | Select-Object -ExpandProperty Name -First $Max)
}

function Get-Definition([string]$Repo, [string]$Name, [string]$ExcludeRegex, [int]$Limit = 3) {
    if (-not $Name -or $Name.Length -lt 3) { return @() }
    $escaped = [regex]::Escape($Name)
    $pat = '(?m)^\s*(export\s+)?(async\s+)?(function|def|func|class|const|let)\s+' + $escaped + '\b'
    $hits = Get-ChildItem -Path $Repo -Recurse -File -Include *.ts, *.tsx, *.js, *.mjs, *.py, *.go, *.rb, *.java, *.c, *.h, *.cpp, *.cc, *.hpp, *.rs -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch $ExcludeRegex } |
        Select-String -Pattern $pat -ErrorAction SilentlyContinue | Select-Object -First $Limit
    $out = @()
    foreach ($h in $hits) {
        $lines = @(Get-Content -LiteralPath $h.Path -Encoding UTF8)
        $start = [Math]::Max(0, $h.LineNumber - 1)
        $end = [Math]::Min($lines.Count - 1, $start + 50)
        if ($start -gt $end) { continue }
        $body = ($lines[$start..$end]) -join "`n"
        if ($body.Length -gt 2500) { $body = $body.Substring(0, 2500) }
        $out += ("// {0}:{1}" -f $h.Path, $h.LineNumber) + "`n" + $body
    }
    return $out
}

function Get-CiContext([string[]]$Lines, [int]$Line) {
    $n = $Lines.Count
    $trig = New-Object System.Collections.Generic.List[string]
    $topPerms = ""; $jobName = ""; $jobIf = ""; $jobPerms = ""

    for ($i = 0; $i -lt $n; $i++) {
        if ($Lines[$i] -match '^["'']?on["'']?\s*:\s*(.*)$') {
            $rest = ($Matches[1] -replace '#.*$', '').Trim()
            if ($rest) {
                $cleaned = $rest -replace '[\[\]\{\}]', ''
                foreach ($t in ($cleaned -split '[,\s]+')) { if ($t -match '^[A-Za-z_]+$') { $trig.Add($t) } }
            } else {
                for ($j = $i + 1; $j -lt $n; $j++) {
                    $l = $Lines[$j]
                    if ($l -match '^\S' -and $l -notmatch '^\s*#') { break }
                    if ($l -match '^  ([A-Za-z_]+)\s*:') { $trig.Add($Matches[1]) }
                    elseif ($l -match '^  -\s*([A-Za-z_]+)') { $trig.Add($Matches[1]) }
                }
            }
            break
        }
    }

    for ($i = 0; $i -lt $n; $i++) {
        if ($Lines[$i] -match '^permissions\s*:\s*(.*)$') {
            $rest = ($Matches[1] -replace '#.*$', '').Trim()
            if ($rest) { $topPerms = $rest }
            else {
                $parts = @()
                for ($j = $i + 1; $j -lt $n; $j++) {
                    if ($Lines[$j] -match '^\S' -and $Lines[$j] -notmatch '^\s*#') { break }
                    if ($Lines[$j].Trim()) { $parts += $Lines[$j].Trim() }
                }
                $topPerms = $parts -join "; "
            }
            break
        }
    }

    $jobsIdx = -1
    for ($i = 0; $i -lt $n; $i++) { if ($Lines[$i] -match '^jobs\s*:\s*$') { $jobsIdx = $i; break } }
    if ($jobsIdx -ge 0) {
        $jobStart = -1
        for ($i = [Math]::Min($Line - 1, $n - 1); $i -gt $jobsIdx; $i--) {
            if ($Lines[$i] -match '^  ([A-Za-z0-9_-]+)\s*:\s*(#.*)?$') { $jobStart = $i; $jobName = $Matches[1]; break }
        }
        if ($jobStart -ge 0) {
            $jobEnd = $n
            for ($j = $jobStart + 1; $j -lt $n; $j++) {
                if ($Lines[$j] -match '^  [A-Za-z0-9_-]+\s*:\s*(#.*)?$') { $jobEnd = $j; break }
            }
            for ($j = $jobStart + 1; $j -lt $jobEnd; $j++) {
                if (-not $jobIf -and $Lines[$j] -match '^    if\s*:\s*(.+?)\s*$') {
                    $jobIf = ($Matches[1] -replace '\s+#.*$', '').Trim()
                    $jobIf = $jobIf -replace '^["'']|["'']$', ''
                }
                if (-not $jobPerms -and $Lines[$j] -match '^    permissions\s*:\s*(.*)$') {
                    $jobPerms = ($Matches[1] -replace '#.*$', '').Trim()
                    if (-not $jobPerms) { $jobPerms = "(block)" }
                }
            }
        }
    }

    $dead = ($jobIf -match '^(\$\{\{\s*)?false\b')
    $reachable = $true
    if ($trig.Count -gt 0) { $reachable = $false; foreach ($t in $trig) { if ($ReachableTriggers -contains $t) { $reachable = $true } } }
    $summary = "on: [{0}]; job: {1}; job if: {2}; job permissions: {3}; workflow permissions: {4}" -f `
        ($trig -join ", "), $(if ($jobName) { $jobName } else { "?" }), $(if ($jobIf) { $jobIf } else { "(none)" }), `
        $(if ($jobPerms) { $jobPerms } else { "(inherit)" }), $(if ($topPerms) { $topPerms } else { "(default)" })
    return [pscustomobject]@{ Triggers = @($trig); JobName = $jobName; JobIf = $jobIf; JobPerms = $jobPerms; TopPerms = $topPerms
        DeadJob = $dead; Reachable = $reachable; Summary = $summary }
}

function Get-Playbook($Lead) {
    if ($Lead.Kind -eq "surface") {
        return @{ Flow = $true; Ask = "Does this handler require authentication, and does it verify that the caller may access the specific object it reads or changes (ownership or role)? If auth may be enforced elsewhere (middleware, framework config, the backend the SDK talks to), say so. Quote the lines you rely on." }
    }
    $id = ([string]$Lead.RuleId).ToLower()
    foreach ($p in $Playbooks) { if ($id -match $p.Match) { return $p } }
    return @{ Flow = $true; Ask = "Can an attacker who is not already running code on the machine reach this code with data they control, and does that cause a security impact?" }
}

function New-Result($Lead, [hashtable]$Over) {
    $r = [ordered]@{
        id = $Lead.Id; kind = $Lead.Kind; rule = $Lead.RuleId; file = $Lead.File; line = $Lead.Line
        tags = ($Lead.Tags -join ","); verdict = "unverified"; impact = "none"; exploitability = "theoretical"
        confidence = "speculative"; score = 0.0; attacker = ""; entry_point = ""; source = ""; flow = ""; sink = ""
        validation = ""; why = ""; missing_context = ""; to_verify = ""; ci = [string]$Lead.CiSummary; class = "signal"
    }
    foreach ($k in $Over.Keys) { $r[$k] = $Over[$k] }
    return [pscustomobject]$r
}

function Set-Score($Res, $Lead) {
    $impactW = @{ none = 0; low = 1; medium = 2; high = 3; critical = 4 }
    $confW = @{ likely = 1.0; speculative = 0.4 }
    $explW = @{ trivial = 1.0; moderate = 0.75; hard = 0.4; theoretical = 0.15 }
    $verdW = @{ potential_vuln = 1.0; suspicious = 0.6; interesting = 0.2 }
    $tagMult = 1.0
    if ($Lead.Tags -contains "web") { $tagMult = 1.25 }
    if ($Lead.Tags -contains "privileged") { $tagMult = 1.25 }
    if ($Lead.Engine -eq "codeql") { $tagMult *= 1.15 }
    if ($Lead.Tags -contains "demo") { $tagMult = 0.5 }
    $s = (Get-Weight $impactW ([string]$Res.impact) 0) * (Get-Weight $confW ([string]$Res.confidence) 0.4) *
        (Get-Weight $explW ([string]$Res.exploitability) 0.15) * (Get-Weight $verdW ([string]$Res.verdict) 0) * $tagMult
    $Res.score = [Math]::Round($s, 3)
}

function Test-JsonScriptTag($Lead) {
    if ($Lead.RuleId -notmatch 'var-in-script-tag|unknown-value-with-script-tag') { return $false }
    if ($Lead.File -notmatch '\.html?$') { return $false }
    if (-not (Test-Path $Lead.File)) { return $false }
    $lines = @(Get-Content -LiteralPath $Lead.File -Encoding UTF8)
    $idx = [int]$Lead.Line - 1
    if ($idx -lt 0 -or $idx -ge $lines.Count) { return $false }
    $start = [Math]::Max(0, $idx - 3)
    for ($i = $start; $i -le $idx; $i++) { if ($lines[$i] -match 'type\s*=\s*["'']application/json["'']') { return $true } }
    return $false
}

function Test-DaemonDockerfile($Lead) {
    if ($Lead.RuleId -notmatch 'missing-user') { return $false }
    if (-not (Test-Path $Lead.File)) { return $false }
    if ((Split-Path $Lead.File -Leaf) -notmatch 'Dockerfile') { return $false }
    $dfText = Get-Content -LiteralPath $Lead.File -Raw -Encoding UTF8
    return ($dfText -match '(?i)\b(sshd|openssh|nginx|apache|bind9|EXPOSE\s+(22|80|443)|port\s+(22|80|443))\b')
}

function Test-AngularTemplate($Lead) {
    if ($Lead.RuleId -notmatch 'var-in-href|var-in-script-tag|unknown-value-with-script-tag|innerhtml|dangerously') { return $false }
    if ($Lead.File -notmatch '\.html?$') { return $false }
    if ($Lead.File -match '(?i)\.component\.html$') { return $true }
    if ($script:RepoRoot -and (Test-Path (Join-Path $script:RepoRoot 'angular.json'))) { return $true }
    return $false
}

function Test-HmacGuardedPickle($Lead) {
    if ($Lead.RuleId -notmatch 'avoid-pickle|deserialization|pickle') { return $false }
    if (-not (Test-Path $Lead.File)) { return $false }
    $lines = @(Get-Content -LiteralPath $Lead.File -Encoding UTF8)
    $idx = [int]$Lead.Line - 1
    if ($idx -lt 0 -or $idx -ge $lines.Count) { return $false }
    $start = [Math]::Max(0, $idx - 15)
    for ($i = $start; $i -le $idx; $i++) {
        if ($lines[$i] -match 'hmac\.(compare_digest|new)\b') { return $true }
        if ($lines[$i] -match '(?i)(verify|validate)[_a-z]*signature\b') { return $true }
    }
    return $false
}

function Test-LoggerIsBenign($Lead) {
    if ($Lead.RuleId -notmatch $LoggerCredRuleRx) { return $false }
    if (-not (Test-Path $Lead.File)) { return $false }
    $lines = @(Get-Content -LiteralPath $Lead.File -Encoding UTF8)
    $idx = [int]$Lead.Line - 1
    if ($idx -lt 0 -or $idx -ge $lines.Count) { return $false }
    $end = [Math]::Min($lines.Count - 1, $idx + 5)
    for ($i = $idx; $i -le $end; $i++) {
        $line = $lines[$i]
        $stripped = $line -replace '"[^"]*"', '' -replace "'[^']*'", ''
        if ($stripped -match $CredNameRx) { return $false }
    }
    return $true
}

# === v3.5 === Rails admin Pundit suppression
function Test-RailsAdminPundit($Lead) {
    if ($Lead.RuleId -notmatch 'check-unscoped-find|unscoped-find') { return $false }
    if ($Lead.Rel -notmatch 'app/controllers/admin/') { return $false }
    return $true
}

# === v3.5 === CSRF GET-only suppression
function Test-CsrfGetOnly($Lead) {
    if ($Lead.RuleId -notmatch 'missing-csrf-protection') { return $false }
    if (-not (Test-Path $Lead.File)) { return $false }
    $lines = @(Get-Content -LiteralPath $Lead.File -Encoding UTF8)
    $hasWrite = $lines | Where-Object { $_ -match '^\s*def\s+(create|update|destroy|delete|post|put|patch|edit|new)\b' }
    if ($hasWrite) { return $false }
    return $true
}

# === v3.5 === Composite action suppression
function Test-CompositeAction($Lead) {
    if ($Lead.RuleId -notmatch 'shell-injection|command-injection') { return $false }
    if ($Lead.Rel -notmatch '^\.github/actions/') { return $false }
    return $true
}

function Get-PreVerdict($Lead) {
    if (-not $DisableSuppressions) {
        if (Test-RailsAdminPundit $Lead) {
            return (New-Result $Lead @{ verdict = "not_vuln"; why = "Admin controller; Pundit authorization enforced by Admin::BaseController and verify_authorized."; class = "dead_code" })
        }
        if (Test-CsrfGetOnly $Lead) {
            return (New-Result $Lead @{ verdict = "not_vuln"; why = "GET-only controller; CSRF protection is not applicable."; class = "dead_code" })
        }
        if (Test-CompositeAction $Lead) {
            return (New-Result $Lead @{ verdict = "not_vuln"; why = "Composite action; inputs are supplied by in-repo callers with literals, not by outside attackers."; class = "dead_code" })
        }
        if (Test-AngularTemplate $Lead) {
            return (New-Result $Lead @{ verdict = "not_vuln"; why = "Angular component template; Angular sanitizes URL and DOM bindings."; class = "dead_code" })
        }
        if (Test-HmacGuardedPickle $Lead) {
            return (New-Result $Lead @{ verdict = "not_vuln"; why = "Deserialization guarded by HMAC verification or signature check above."; class = "dead_code" })
        }
        if (Test-LoggerIsBenign $Lead) {
            return (New-Result $Lead @{ verdict = "not_vuln"; why = "Logger call only mentions credential words in string literals; no credential value is logged."; class = "dead_code" })
        }
        if ($Lead.RuleId -match 'detected-private-key|insecure-file-permissions' -and $Lead.Rel -match $FixturePathRx) {
            return (New-Result $Lead @{ verdict = "not_vuln"; why = "Test fixture path; not a shipped surface."; class = "dead_code" })
        }
        if (Test-JsonScriptTag $Lead) {
            return (New-Result $Lead @{ verdict = "not_vuln"; why = "Non-executable script type (application/json); not a JS injection surface."; class = "dead_code" })
        }
        if (Test-DaemonDockerfile $Lead) {
            return (New-Result $Lead @{ verdict = "not_vuln"; why = "Dockerfile builds a network daemon needing privileged ports or a specific user."; class = "dead_code" })
        }
        if ($Lead.RuleId -match 'dynamic-urllib-use-detected' -and $script:RepoTypeName -eq 'cli_desktop') {
            return (New-Result $Lead @{ verdict = "not_vuln"; why = "Desktop client calling a fixed or configured endpoint with its own credentials."; class = "dead_code" })
        }
        if (-not $NoRuleCaps -and $script:RuleCaps.ContainsKey($Lead.RuleId)) {
            return (New-Result $Lead @{ verdict = "interesting"; impact = "low"; exploitability = "hard"; confidence = "speculative"
                why = "Auto-capped: " + $script:RuleCaps[$Lead.RuleId]; class = "hygiene" })
        }
    }

    foreach ($t in @("test", "docs", "generated")) {
        if ($Lead.Tags -contains $t) {
            return (New-Result $Lead @{ verdict = "filtered_by_tag"; why = "File tagged '$t'; not a shipped surface." })
        }
    }
    if (-not $Lead.Ci -and $Lead.RuleId -match $CiHygieneRx) {
        return (New-Result $Lead @{ verdict = "interesting"; impact = "low"; exploitability = "hard"; confidence = "likely"
            why = "Supply-chain hardening recommendation, not a vulnerability reachable by an outside attacker."; class = "hygiene" })
    }
    if ($Lead.Ci) {
        $ci = $Lead.Ci
        if ($ci.DeadJob) {
            return (New-Result $Lead @{ verdict = "not_vuln"; why = "Job is disabled (if: $($ci.JobIf))."; class = "dead_code" })
        }
        if ($Lead.RuleId -match $CiHygieneRx) {
            return (New-Result $Lead @{ verdict = "interesting"; impact = "low"; exploitability = "hard"; confidence = "likely"
                why = "Supply-chain hygiene (unpinned or inherited). Rarely accepted by bounty programs on its own."; class = "hygiene" })
        }
        if (-not $ci.Reachable -and $Lead.RuleId -notmatch 'secret') {
            return (New-Result $Lead @{ verdict = "interesting"; impact = "low"; exploitability = "hard"; confidence = "speculative"
                why = "Workflow triggers are not attacker-reachable ($($ci.Triggers -join ', ')). A reusable workflow could still be called with untrusted input; check its callers."
                missing_context = "workflows that call this one with PR data" })
        }
    }
    return $null
}

function Resolve-Result($Lead, $T2) {
    $pb = Get-Playbook $Lead
    if (-not $T2) { return (New-Result $Lead @{ why = "Model returned no valid JSON." }) }
    $over = @{
        attacker = ([string]$T2.attacker).ToLower(); entry_point = [string]$T2.entry_point
        source = [string]$T2.source_quote; flow = [string]$T2.flow_quote; sink = [string]$T2.sink_quote
        validation = [string]$T2.validation_seen; why = [string]$T2.why
        missing_context = (Join-Field $T2.missing_context); to_verify = [string]$T2.to_verify
    }
    $verdict = ([string]$T2.verdict).ToLower()
    $impact = ([string]$T2.impact).ToLower()
    $expl = ([string]$T2.exploitability).ToLower()
    if ($AllowedVerdicts -notcontains $verdict) {
        $over.why += " [invalid verdict from model]"
        return (New-Result $Lead $over)
    }
    if (@("none", "low", "medium", "high", "critical") -notcontains $impact) { $impact = "low" }
    if (@("trivial", "moderate", "hard", "theoretical") -notcontains $expl) { $expl = "theoretical" }
    $confidence = "speculative"
    $notes = New-Object System.Collections.Generic.List[string]
    if ($script:AttackerList -notcontains $over.attacker) {
        $notes.Add("attacker label not valid for this repo type"); $over.attacker = "invalid"
    }

    if ($verdict -ne "not_vuln") {
        $srcOk = Test-QuoteFound $over.source $Lead.Hay
        $snkOk = Test-QuoteFound $over.sink $Lead.Hay
        if ($pb.Flow) {
            $flowOk = $false
            if ($srcOk -and $snkOk) {
                $sid = Get-Identifiers (Remove-LinePrefix $over.source)
                $kid = Get-Identifiers (Remove-LinePrefix $over.sink)
                if (Test-Overlap $sid $kid) { $flowOk = $true }
                elseif (Test-QuoteFound $over.flow $Lead.Hay) {
                    $fid = Get-Identifiers (Remove-LinePrefix $over.flow)
                    if ((Test-Overlap $fid $sid) -and (Test-Overlap $fid $kid)) { $flowOk = $true }
                }
            }
            if (-not $flowOk) {
                $over.why += " [no verified source-to-sink line in the shown code]"
                if (-not $over.missing_context) { $over.missing_context = "the line connecting the input to the sensitive call" }
                $over.verdict = "unverified"; $over.impact = "none"; $over.exploitability = "theoretical"; $over.confidence = "speculative"
                return (New-Result $Lead $over)
            }
        } elseif (-not $snkOk) {
            $over.why += " [sink quote not found in the shown code]"
            $over.verdict = "unverified"; $over.impact = "none"; $over.exploitability = "theoretical"; $over.confidence = "speculative"
            return (New-Result $Lead $over)
        }

        if ($pb.Flow) {
            if (($script:Outside -notcontains $over.attacker) -and ($verdict -eq "potential_vuln" -or $verdict -eq "suspicious")) {
                $verdict = "interesting"; $notes.Add("capped: no outside attacker identified for this repo type")
            }
            if ($verdict -eq "potential_vuln" -and ([string]::IsNullOrWhiteSpace($over.entry_point) -or $over.entry_point -eq "unclear")) {
                $verdict = "suspicious"; $notes.Add("capped: entry point unclear")
            }
        }
        if (($Lead.Tags -contains "demo" -or $Lead.Tags -contains "build") -and ($verdict -eq "potential_vuln" -or $verdict -eq "suspicious")) {
            $verdict = "interesting"; $notes.Add("capped: demo or build path, not a shipped surface")
        }
        if ($verdict -eq "potential_vuln" -or $verdict -eq "suspicious") {
            if ($pb.Flow) {
                $noVal = ($over.validation -match '(?i)^\s*none|none seen|no (validation|sanitiz)')
                if (($script:Outside -contains $over.attacker) -and $noVal) { $confidence = "likely" }
            } elseif ($verdict -eq "potential_vuln") { $confidence = "likely" }
        }
    }
    if ($verdict -eq "not_vuln") { $impact = "none" }
    if ($notes.Count -gt 0) { $over.why += " [" + ($notes -join "; ") + "]" }
    $over.verdict = $verdict; $over.impact = $impact; $over.exploitability = $expl; $over.confidence = $confidence
    return (New-Result $Lead $over)
}

function Test-Fast([string]$Snippet) {
    $prompt = @"
Does this code handle external or untrusted input AND pass it to a dangerous
operation (SQL, shell command, file path, deserialization, HTTP fetch, auth decision)?
Answer JSON only: {"relevant": true, "reason": "one line"}

CODE:
$Snippet
"@
    return (Invoke-Llm $FastModel $prompt)
}

function Test-Deep($Lead) {
    $pb = Get-Playbook $Lead
    $ciBlock = ""
    if ($Lead.CiSummary) { $ciBlock = "WORKFLOW CONTEXT (extracted by script, trust it): $($Lead.CiSummary)" }
    $callerBlock = ($Lead.Callers -join "`n")
    $prompt = @"
You are a careful security code reviewer. Be skeptical: most static-analysis hits are not vulnerabilities.
A finding only matters if an OUTSIDE attacker can reach it. Local config, developer CLI flags, build scripts,
tests, demos and code that already requires the attacker to run code on the machine do NOT count.
Libraries and SDKs are not the authorization boundary; the service or backend they talk to is.

REPO TYPE: $($script:RepoTypeName)
ATTACKER MODEL: $($script:AttackerGuidance)

FILE TAGS: $($Lead.Tags -join ', ')
$ciBlock
STATIC ANALYSIS HINT: $($Lead.Hint)
QUESTION TO ANSWER: $($pb.Ask)

Rules:
- Quote code exactly, WITHOUT leading line-number prefixes. Quote only code shown below.
- source_quote: the exact line where attacker data enters. sink_quote: the exact line of the sensitive operation.
- flow_quote: the exact line where the value reaches the sink or is passed to the function containing it. If no such line is shown, leave source_quote, flow_quote and sink_quote empty and use verdict not_vuln or interesting.
- Never invent files, functions or data flows. List what you could not see in missing_context.
- impact is the realistic worst case if exploitable. exploitability is how hard it is for the attacker.

Answer JSON only:
{"attacker": "$($script:AttackerOptions)",
 "entry_point": "where attacker data enters (route, header, file format, message) or unclear",
 "source_quote": "...", "flow_quote": "...", "sink_quote": "...",
 "validation_seen": "checks between source and sink, or none seen",
 "verdict": "interesting|suspicious|potential_vuln|not_vuln",
 "exploitability": "trivial|moderate|hard|theoretical",
 "impact": "none|low|medium|high|critical",
 "why": "two sentences maximum",
 "missing_context": ["things you could not see"],
 "to_verify": "the single most important thing a human must check next"}

CODE:
$($Lead.Snippet)

CALLERS:
$callerBlock
"@
    return (Invoke-Llm $DeepModel $prompt)
}

function Get-SurfaceLeads([string]$Repo, [string]$Root, [string]$ExcludeRegex, [int]$Max, [string]$MapFile) {
    $files = Get-ChildItem -Path $Repo -Recurse -File -Include *.js, *.mjs, *.ts, *.tsx, *.java, *.py, *.php, *.go, *.rb -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch $ExcludeRegex -and $_.Name -notmatch '\.(test|spec)\.' }
    $routeRx = $RouteRx
    $authRx = '(?i)auth|session|token|jwt|login|permission|\brole|isAdmin|PreAuthorize|Secured|requireUser|currentUser|principal|authorize|guard|verify|middleware'
    $idRx = '(?i)req\.(params|query|body)|params\.|@PathVariable|@RequestParam|@RequestBody|request\.(args|json|form|GET|POST)|\$_(GET|POST|REQUEST)|searchParams|await\s+request\.json'
    $dataRx = '(?i)\.(find|findOne|findById|get|select|delete|update|remove|query|document|exec|raw)\s*\(|SELECT\s|DELETE\s|UPDATE\s|repository\.|\.save\('

    $hits = @($files | Select-String -Pattern $routeRx -ErrorAction SilentlyContinue)
    $script:RouteCount = $hits.Count
    $mapLines = @($hits | ForEach-Object { "{0}:{1}: {2}" -f $_.Path, $_.LineNumber, $_.Line.Trim() })
    $mapHead = "# Attack surface map ({0} route-like entry points)" -f $hits.Count
    (@($mapHead, "") + $mapLines) -join "`n" | Set-Content -Path $MapFile -Encoding UTF8

    $skipTags = @("demo", "test", "docs", "generated", "build", "ci")
    if (-not $SurfaceInSdk) { $skipTags += "sdk" }
    $fileCache = @{}
    $cands = @()
    foreach ($h in $hits) {
        $tags = Get-Tags (Get-RelPath $h.Path $Root)
        $skipThis = $false
        foreach ($t in $tags) { if ($skipTags -contains $t) { $skipThis = $true } }
        if ($skipThis) { continue }
        if (-not $fileCache.ContainsKey($h.Path)) { $fileCache[$h.Path] = @(Get-Content -LiteralPath $h.Path -Encoding UTF8) }
        $lines = $fileCache[$h.Path]
        if ($lines.Count -eq 0) { continue }
        $startIdx = [Math]::Max(0, $h.LineNumber - 1)
        $endIdx = [Math]::Min($lines.Count - 1, $startIdx + 40)
        if ($startIdx -gt $endIdx) { continue }
        $body = ($lines[$startIdx..$endIdx]) -join "`n"
        $headEnd = [Math]::Min($lines.Count - 1, 59)
        $head = ($lines[0..$headEnd]) -join "`n"
        if (($body + "`n" + $head) -match $authRx) { continue }
        if ($body -notmatch $idRx) { continue }
        $score = 1
        if ($body -match $dataRx) { $score = 2 }
        $buf = New-Object System.Collections.Generic.List[string]
        for ($n = $startIdx; $n -le $endIdx; $n++) { $row = "{0}: {1}" -f ($n + 1), $lines[$n]; $buf.Add($row) }
        $snippet = $buf -join "`n"
        if ($snippet.Length -gt 3500) { $snippet = $snippet.Substring(0, 3500) }
        $cands += [pscustomobject]@{ Path = $h.Path; Line = $h.LineNumber; Score = $score; Snippet = $snippet; Text = ($lines -join "`n"); Tags = $tags }
    }
    return @($cands | Sort-Object Score -Descending | Select-Object -First $Max)
}

function Update-RuleHistory([string]$HistFile, $Results, [string]$Repo, [string]$Commit, [string]$Type) {
    $kept = @()
    if (Test-Path $HistFile) {
        foreach ($ln in (Get-Content $HistFile -Encoding UTF8)) {
            if (-not $ln.Trim()) { continue }
            try { $o = $ln | ConvertFrom-Json; if (-not ($o.repo -eq $Repo -and $o.commit -eq $Commit)) { $kept += $ln } } catch { }
        }
    }
    $new = @()
    foreach ($g in ($Results | Group-Object rule)) {
        $v = @($g.Group)
        $rec = [ordered]@{
            repo = $Repo; commit = $Commit; type = $Type; rule = $g.Name; leads = $v.Count
            potential = @($v | Where-Object { $_.verdict -eq "potential_vuln" }).Count
            suspicious = @($v | Where-Object { $_.verdict -eq "suspicious" }).Count
            interesting = @($v | Where-Object { $_.verdict -eq "interesting" }).Count
            not_vuln = @($v | Where-Object { $_.verdict -eq "not_vuln" }).Count
            unverified = @($v | Where-Object { $_.verdict -eq "unverified" }).Count
            filtered = @($v | Where-Object { $_.verdict -eq "filtered_by_tag" }).Count
        }
        $new += ([pscustomobject]$rec | ConvertTo-Json -Compress)
    }
    ($kept + $new) | Set-Content -Path $HistFile -Encoding UTF8
    $all = @()
    foreach ($ln in ($kept + $new)) { try { $all += ($ln | ConvertFrom-Json) } catch { } }
    $agg = @()
    foreach ($g in ($all | Group-Object { "{0} [{1}]" -f $_.rule, $_.type })) {
        $items = @($g.Group)
        $agg += [pscustomobject]@{
            rule = $g.Name
            repos = @($items | Select-Object -ExpandProperty repo -Unique).Count
            leads = [int](($items | Measure-Object -Property leads -Sum).Sum)
            signal = [int](($items | Measure-Object -Property potential -Sum).Sum) + [int](($items | Measure-Object -Property suspicious -Sum).Sum)
            dismissed = [int](($items | Measure-Object -Property not_vuln -Sum).Sum) + [int](($items | Measure-Object -Property interesting -Sum).Sum)
        }
    }
    return @($agg | Sort-Object leads -Descending | Select-Object -First 12)
}

function Get-RuleCaps([string]$HistFile, [int]$MinLeads = 10, [int]$MinRepos = 2) {
    $caps = @{}
    if (-not (Test-Path $HistFile)) { return $caps }
    try {
        $all = @()
        foreach ($ln in (Get-Content $HistFile -Encoding UTF8)) {
            if (-not $ln.Trim()) { continue }
            try { $all += ($ln | ConvertFrom-Json) } catch { }
        }
        foreach ($g in ($all | Group-Object rule)) {
            $items = @($g.Group)
            $totalLeads = [int](($items | Measure-Object -Property leads -Sum).Sum)
            $totalSignal = [int](($items | Measure-Object -Property potential -Sum).Sum) + [int](($items | Measure-Object -Property suspicious -Sum).Sum)
            $repos = @($items | Select-Object -ExpandProperty repo -Unique).Count
            if ($totalLeads -ge $MinLeads -and $totalSignal -eq 0 -and $repos -ge $MinRepos) {
                $caps[$g.Name] = ("{0} leads across {1} repos with 0 signal" -f $totalLeads, $repos)
            }
        }
    } catch { }
    return $caps
}

function Get-ExtSum($Map, [string[]]$Names) { $t = 0; foreach ($n in $Names) { if ($Map.ContainsKey($n)) { $t += $Map[$n] } }; return $t }

function Get-RepoTypeInfo([string]$Root, $ExtCounts, [string]$ExcludeRegex, [string]$Override) {
    $map = @{}
    foreach ($g in $ExtCounts) { $map[([string]$g.Name).ToLower()] = [int]$g.Count }
    $codeExts = @(".java", ".py", ".js", ".mjs", ".ts", ".tsx", ".php", ".go", ".rb", ".sh", ".bash", ".zsh", ".rs", ".c", ".cpp", ".cs")
    $code = Get-ExtSum $map $codeExts
    $shell = Get-ExtSum $map @(".sh", ".bash", ".zsh")
    $desktop = Get-ExtSum $map @(".desktop", ".service", ".timer", ".install")
    $tf = Get-ExtSum $map @(".tf", ".tfvars")

    $files = @(Get-ChildItem -Path $Root -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch $ExcludeRegex })
    $binNoExt = @($files | Where-Object { $_.Extension -eq "" -and $_.FullName -match '\\(bin|sbin|libexec)\\' }).Count
    $helm = @($files | Where-Object { $_.Name -in @("Chart.yaml", "kustomization.yaml", "docker-compose.yml", "docker-compose.yaml") }).Count
    $manifests = @($files | Where-Object { $_.Name -in @("package.json", "pyproject.toml", "setup.py", "pom.xml", "build.gradle", "go.mod", "Cargo.toml", "composer.json", "Gemfile", "requirements.txt") })

    $serverDeps = $false
    foreach ($m in ($manifests | Select-Object -First 40)) {
        $txt = [string](Get-Content -LiteralPath $m.FullName -Raw -ErrorAction SilentlyContinue)
        if ($txt -match $ServerDepRx) { $serverDeps = $true; break }
    }

    $routeFiles = @($files | Where-Object { $codeExts -contains $_.Extension.ToLower() } | Where-Object {
            $t = Get-Tags (Get-RelPath $_.FullName $Root)
            -not ($t -contains "test" -or $t -contains "demo" -or $t -contains "docs" -or $t -contains "generated")
        })
    $routes = 0
    if ($routeFiles.Count -gt 0) { $routes = @($routeFiles | Select-String -Pattern $RouteRx -ErrorAction SilentlyContinue).Count }

    $isVsExt = $false
    foreach ($m2 in ($manifests | Where-Object { $_.Name -eq "package.json" } | Select-Object -First 40)) {
        $txt2 = [string](Get-Content -LiteralPath $m2.FullName -Raw -ErrorAction SilentlyContinue)
        if ($txt2 -match '"engines"\s*:\s*\{[^}]*"vscode"') { $isVsExt = $true; break }
    }
    $shellish = $shell + $binNoExt + $desktop
    $denom = [Math]::Max(1, $code + $binNoExt + $desktop)
    $type = "library"
    if ($isVsExt -and $routes -lt 3) { $type = "vscode_extension" }
    elseif ($routes -ge 3 -or $serverDeps) { $type = "service" }
    elseif ($shellish -ge 5 -and (($shellish / $denom) -ge 0.3)) { $type = "cli_desktop" }
    elseif (($tf + $helm) -ge 5) { $type = "infra" }
    elseif ($manifests.Count -gt 0) { $type = "library" }
    elseif ($shellish -gt 0) { $type = "cli_desktop" }

    $how = "auto-detected"
    if ($Override -ne "auto") { $type = $Override; $how = "set with -RepoType" }
    $evidence = "{0}; routes={1}, server frameworks in manifests={2}, shell-like files={3}, unit or desktop files={4}, code files={5}, infra files={6}, vscode manifest={7}" -f `
        $how, $routes, $serverDeps, ($shell + $binNoExt), $desktop, $code, ($tf + $helm), $isVsExt
    return [pscustomobject]@{ Type = $type; Evidence = $evidence; Routes = $routes }
}

function Get-AttackerSpec([string]$Type) {
    $remote = @("remote_unauthenticated", "remote_authenticated", "untrusted_content")
    $remoteOptions = "remote_unauthenticated|remote_authenticated|untrusted_content|local_only|none"
    if ($Type -eq "library") {
        return @{ Options = "untrusted_content|local_only|none"; Outside = @("untrusted_content")
            Guidance = "This is a library. It is only exploitable if untrusted data that an application would plausibly pass into this API can cause harm (injection, path traversal, memory safety, ReDoS, prototype pollution). Misuse of the API by the developer who calls it is not a library vulnerability." }
    }
    if ($Type -eq "cli_desktop") {
        return @{ Options = "other_local_user|untrusted_content|privilege_boundary|local_only|none"
            Outside = @("other_local_user", "untrusted_content", "privilege_boundary")
            Guidance = "This is a desktop or command-line tool that runs on the user's own machine. There is no remote attacker unless the tool fetches or parses outside data. Real attackers are: another local user (shared temp directory, predictable file names, world-readable secrets), untrusted content the tool trusts unsafely (downloaded files, fetched data, archives, file names), and a privilege boundary (code that runs as root through sudo, pkexec, setuid, polkit or a system service, on input a less-privileged user controls). The file tag privileged means the file uses such mechanisms. A script that does what the user could already do by hand is not a vulnerability. A client calling a fixed endpoint with its own credentials is not a vulnerability." }
    }
    if ($Type -eq "vscode_extension") {
        return @{ Options = "untrusted_content|workspace_trust|local_only|none"; Outside = @("untrusted_content", "workspace_trust")
            Guidance = "This is an editor extension. It runs on the developer's machine with the user's credentials. The extension host and the user's own settings are trusted. Untrusted data is: responses from the remote service it talks to, the contents of whatever workspace the user opens, and links or URIs that external pages can trigger. Webviews can run script and message the extension host. Real bugs look like: untrusted data injected into webview HTML or script without escaping or a strict content security policy, message handlers that act on unvalidated payloads, URIs opened without a scheme and host check, commands or file operations built from workspace configuration, and credentials sent to the wrong host or written to logs." }
    }
    if ($Type -eq "infra") {
        return @{ Options = $remoteOptions; Outside = $remote
            Guidance = "This is infrastructure or deployment configuration. Issues matter when a default or example configuration exposes a service publicly, grants excessive permissions, disables authentication or encryption, or embeds real secrets." }
    }
    return @{ Options = $remoteOptions; Outside = $remote
        Guidance = "This is a network service or web app. Outside attackers are remote users (unauthenticated, or authenticated as a normal user) and untrusted content such as uploads or webhook payloads." }
}

function Get-LocalLeads([string]$Repo, [string]$Root, [string]$ExcludeRegex, [int]$Max, [string]$Type) {
    $isExt = ($Type -eq "vscode_extension")
    $shellExts = @(".sh", ".bash", ".zsh", ".py", ".service", ".timer", ".desktop", ".install")
    $extExts = @(".ts", ".tsx", ".js", ".mjs", ".cjs", ".html", ".vue", ".svelte")
    $candidates = @(Get-ChildItem -Path $Repo -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch $ExcludeRegex -and $_.Length -lt 300000 -and $_.Name -notmatch '\.min\.' })
    $files = @()
    foreach ($f in $candidates) {
        $tg = Get-Tags (Get-RelPath $f.FullName $Root)
        if ($tg -contains "test" -or $tg -contains "docs" -or $tg -contains "generated") { continue }
        $ext = $f.Extension.ToLower()
        if ($isExt) { if ($extExts -contains $ext) { $files += $f }; continue }
        if (($shellExts -contains $ext) -or $f.Name -eq "PKGBUILD") { $files += $f; continue }
        if ($ext -eq "") {
            $first = @(Get-Content -LiteralPath $f.FullName -TotalCount 1 -ErrorAction SilentlyContinue)
            if ($first.Count -gt 0 -and ([string]$first[0]).StartsWith("#!")) { $files += $f }
        }
    }

    if ($isExt) {
        $checks = @(
            @{ Rule = "ext-webview-html"; Weight = 2; Rx = '(?i)webview\.html\s*=|<script[^>\r\n]*>[^<\r\n]*\$\{|innerHTML\s*=|insertAdjacentHTML|dangerouslySetInnerHTML|\bv-html\b'; Hint = "builds or injects HTML or script from variables" },
            @{ Rule = "ext-enable-scripts"; Weight = 1; Rx = 'enableScripts\s*:\s*true'; Hint = "webview scripts are enabled" },
            @{ Rule = "ext-postmessage"; Weight = 2; Rx = 'onDidReceiveMessage\s*\(|addEventListener\(\s*["'']message["'']'; Hint = "message handler between a webview and the extension" },
            @{ Rule = "ext-open-external"; Weight = 1; Rx = 'openExternal\s*\(|env\.openExternal'; Hint = "opens a link or URI" },
            @{ Rule = "ext-exec"; Weight = 2; Rx = '\b(execSync|execFile|exec|spawn|spawnSync)\s*\('; NeedFile = 'child_process'; Hint = "starts a process" },
            @{ Rule = "ext-uri-handler"; Weight = 2; Rx = 'registerUriHandler'; Hint = "handles links that external pages can trigger" },
            @{ Rule = "ext-token-log"; Weight = 1; Rx = '(?i)(console\.(log|info|debug)|logger\.(debug|info)|appendLine)\s*\([^)\r\n]*(token|password|secret|authorization)'; Hint = "may write a credential to a log" }
        )
    } else {
        $checks = @(
            @{ Rule = "local-priv-exec"; Weight = 2; Rx = '(?i)\b(sudo|pkexec|doas)\b[^#\r\n]*\$'; Hint = "elevated command built with a variable" },
            @{ Rule = "local-pipe-shell"; Weight = 2; Rx = '(?i)\b(curl|wget)\b[^|\r\n]*\|\s*(sudo\s+)?(ba|z)?sh\b|\beval\s+"?\$\(\s*(curl|wget)'; Hint = "downloads code and runs it in a shell" },
            @{ Rule = "local-tmp"; Weight = 1; Rx = '(/tmp|/var/tmp)/[A-Za-z0-9_.${}-]+'; NoFile = 'mktemp'; Hint = "fixed path in the shared temp directory" },
            @{ Rule = "local-chmod"; Weight = 1; Rx = '\bchmod\s+(-R\s+)?(0?777|0?666|a\+w|o\+w)\b'; Hint = "makes a file or directory writable by others" },
            @{ Rule = "local-eval"; Weight = 1; Rx = '\beval\s+[^#\r\n]*\$|\b(ba)?sh\s+-c\s+"[^"\r\n]*\$'; Hint = "evaluates a string that contains a variable" }
        )
    }

    $textCache = @{}
    $groups = @{}
    foreach ($c in $checks) {
        $hits = @($files | Select-String -Pattern $c.Rx -ErrorAction SilentlyContinue)
        foreach ($h in $hits) {
            $tl = $h.Line.TrimStart()
            if ($tl.StartsWith("#") -or $tl.StartsWith("//") -or $tl.StartsWith("*") -or $tl.StartsWith("/*")) { continue }
            if (-not $textCache.ContainsKey($h.Path)) {
                $textCache[$h.Path] = [pscustomobject]@{
                    Text = [string](Get-Content -LiteralPath $h.Path -Raw -Encoding UTF8)
                    Lines = @(Get-Content -LiteralPath $h.Path -Encoding UTF8)
                }
            }
            $tc = $textCache[$h.Path]
            if ($c.NoFile -and $tc.Text -match $c.NoFile) { continue }
            if ($c.NeedFile -and $tc.Text -notmatch $c.NeedFile) { continue }
            $gk = ("{0}|{1}" -f $c.Rule, $h.Path)
            if (-not $groups.ContainsKey($gk)) { $groups[$gk] = [pscustomobject]@{ Check = $c; Path = $h.Path; Hits = (New-Object System.Collections.ArrayList) } }
            [void]$groups[$gk].Hits.Add([int]$h.LineNumber)
        }
    }

    $cands = @()
    foreach ($g in $groups.Values) {
        $tc = $textCache[$g.Path]
        $lines = $tc.Lines
        $score = [int]$g.Check.Weight
        if ($isExt) { if ($tc.Text -match '(?i)graphql|fetch\(|axios|response|markdown|webview') { $score++ } }
        elseif ($tc.Text -match '\$\{?[1-9@*]') { $score++ }
        $lineNums = @($g.Hits | Sort-Object)
        foreach ($ln in @($lineNums | Select-Object -First 2)) {
            $startIdx = [Math]::Max(0, $ln - 1 - 15)
            $endIdx = [Math]::Min($lines.Count - 1, $ln - 1 + 15)
            if ($startIdx -gt $endIdx) { continue }
            $buf = New-Object System.Collections.Generic.List[string]
            for ($k = $startIdx; $k -le $endIdx; $k++) { $row = "{0}: {1}" -f ($k + 1), $lines[$k]; $buf.Add($row) }
            $snippet = $buf -join "`n"
            if ($snippet.Length -gt 3500) { $snippet = $snippet.Substring(0, 3500) }
            $cands += [pscustomobject]@{ Rule = $g.Check.Rule; Hint = $g.Check.Hint; Path = $g.Path; Line = [int]$ln; Score = $score
                Snippet = $snippet; Text = $tc.Text; GroupHits = $lineNums.Count; GroupLines = $lineNums }
        }
    }
    return @($cands | Sort-Object Score -Descending | Select-Object -First $Max)
}


function Test-CodeQLCli {
    try {
        $old = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        & codeql --version 2>&1 | Out-Null
        $ok = ($LASTEXITCODE -eq 0)
        $ErrorActionPreference = $old
        return $ok
    } catch { return $false }
}

function Get-CodeQLLanguage($ExtCounts) {
    $map = @{}
    foreach ($g in $ExtCounts) { $map[([string]$g.Name).ToLower()] = [int]$g.Count }
    $buckets = [ordered]@{
        javascript = @(".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")
        python     = @(".py")
        java       = @(".java")
        csharp     = @(".cs")
        go         = @(".go")
        ruby       = @(".rb")
        cpp        = @(".c", ".h", ".cpp", ".cc", ".hpp")
    }
    $counts = @{}
    foreach ($lang in $buckets.Keys) {
        $t = 0
        foreach ($e in $buckets[$lang]) { if ($map.ContainsKey($e)) { $t += $map[$e] } }
        $counts[$lang] = $t
    }
    $best = $counts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1
    if (-not $best -or $best.Value -eq 0) { return $null }
    return $best.Key
}

function Invoke-CodeQLScan([string]$Root, [string]$WorkDir, [string]$RepoName, [string]$ReportDir, [string]$Language, [string]$Suite) {
    $dbDir = Join-Path $WorkDir ("_codeql-db-" + $RepoName + "-" + $Language)
    $sarifOut = Join-Path $ReportDir "$RepoName.codeql.$Language.sarif.json"
    $old = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    if (-not (Test-Path (Join-Path $dbDir "codeql-database.yml"))) {
        if (Test-Path $dbDir) { Remove-Item $dbDir -Recurse -Force -ErrorAction SilentlyContinue }
        Write-Step "CodeQL: building database ($Language) -- this can take several minutes"
        $dbArgs = @("database", "create", $dbDir, "--language=$Language", "--source-root=$Root", "--overwrite")
        if ($Language -in @("javascript", "python")) { $dbArgs += "--build-mode=none" }
        & codeql @dbArgs 2>&1 | ForEach-Object { Write-Host "    $_" }
        if (-not (Test-Path (Join-Path $dbDir "codeql-database.yml"))) {
            $ErrorActionPreference = $old
            Write-Warning "CodeQL database build failed. For compiled languages (java, csharp, go, cpp) the repo usually needs its real build command via --command; skipping CodeQL for this run."
            return $null
        }
    } else {
        Write-Step "CodeQL: reusing existing database at $dbDir"
    }
    Write-Step "CodeQL: running the $Suite query suite (this can take a while on the first run while packs download)"
    $queryPack = "codeql/$Language-queries:codeql-suites/$Language-$Suite.qls"
    & codeql database analyze $dbDir $queryPack --format=sarifv2.1.0 --output=$sarifOut --threads=0 2>&1 | ForEach-Object { Write-Host "    $_" }
    $ErrorActionPreference = $old
    if (-not (Test-Path $sarifOut)) {
        Write-Warning "CodeQL analyze produced no SARIF output. The query pack name '$queryPack' may not match this CodeQL CLI version -- check 'codeql resolve qlpacks' and adjust, or pass -CodeQLSuite security-and-quality."
        return $null
    }
    return $sarifOut
}

function ConvertFrom-CodeQLSarif([string]$SarifPath, [string]$Root) {
    $out = @()
    try { $doc = Get-Content -LiteralPath $SarifPath -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch { Write-Warning "Could not parse CodeQL SARIF: $($_.Exception.Message)"; return $out }
    $sevMap = @{ error = "ERROR"; warning = "WARNING"; note = "INFO" }
    foreach ($run in $doc.runs) {
        foreach ($res in $run.results) {
            $loc = $res.locations | Select-Object -First 1
            if (-not $loc) { continue }
            $uri = [string]$loc.physicalLocation.artifactLocation.uri
            if (-not $uri) { continue }
            $full = Join-Path $Root ($uri -replace '/', '\')
            if (-not (Test-Path $full)) { continue }
            $sLine = [int]$loc.physicalLocation.region.startLine
            $eLine = if ($loc.physicalLocation.region.endLine) { [int]$loc.physicalLocation.region.endLine } else { $sLine }
            $msg = [string]$res.message.text
            $sev = if ($sevMap.ContainsKey([string]$res.level)) { $sevMap[[string]$res.level] } else { "WARNING" }

            $pathText = New-Object System.Collections.Generic.List[string]
            $pathLines = New-Object System.Collections.Generic.List[string]
            if ($res.codeFlows -and $res.codeFlows.Count -gt 0 -and $res.codeFlows[0].threadFlows -and $res.codeFlows[0].threadFlows.Count -gt 0) {
                foreach ($tf in $res.codeFlows[0].threadFlows[0].locations) {
                    $pl = $tf.location.physicalLocation
                    if (-not $pl) { continue }
                    $pUri = [string]$pl.artifactLocation.uri
                    $pLine = [int]$pl.region.startLine
                    $pFull = Join-Path $Root ($pUri -replace '/', '\')
                    $lineText = ""
                    if (Test-Path $pFull) {
                        $allLines = @(Get-Content -LiteralPath $pFull -Encoding UTF8)
                        if ($pLine -ge 1 -and $pLine -le $allLines.Count) { $lineText = $allLines[$pLine - 1].Trim() }
                    }
                    $pathText.Add(("{0}:{1}: {2}" -f $pUri, $pLine, $lineText))
                    if ($lineText) { $pathLines.Add($lineText) }
                }
            }
            $pathBlock = if ($pathText.Count -gt 0) { "Dataflow path (CodeQL-traced, source to sink, trust these steps):`n" + ($pathText -join "`n") } else { "" }
            $fullMsg = $msg
            if ($pathBlock) { $fullMsg = $msg + "`n`n" + $pathBlock }

            $entry = [pscustomobject]@{
                path     = $full
                start    = [pscustomobject]@{ line = $sLine }
                end      = [pscustomobject]@{ line = $eLine }
                check_id = "codeql-" + ([string]$res.ruleId -replace '[^\w./-]', '')
                extra    = [pscustomobject]@{ message = $fullMsg; severity = $sev }
                Engine   = "codeql"
            }
            if ($pathLines.Count -gt 0) { $entry | Add-Member -NotePropertyName CqLines -NotePropertyValue (@($pathLines)) }
            $out += $entry
        }
    }
    return $out
}

function Get-DockerRunInfo([string]$Root) {
    $compose = Get-ChildItem -Path $Root -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^(docker-)?compose\.ya?ml$' } | Select-Object -First 1
    $dockerfiles = @(Get-ChildItem -Path $Root -Recurse -File -Filter "Dockerfile*" -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '\\(node_modules|\.git)\\' } | Select-Object -First 5)
    if (-not $compose -and $dockerfiles.Count -eq 0) { return $null }
    $lines = New-Object System.Collections.Generic.List[string]
    if ($compose) {
        $lines.Add("Compose file: $($compose.Name)")
        $lines.Add('Try: docker compose -f "' + $compose.FullName + '" up --build')
        $ports = @(Select-String -Path $compose.FullName -Pattern '-\s*["'']?(\d{2,5}):(\d{2,5})' -ErrorAction SilentlyContinue |
            ForEach-Object { $_.Matches[0].Groups[1].Value } | Select-Object -Unique)
        if ($ports.Count -gt 0) { $lines.Add("Host ports published in the compose file: " + ($ports -join ", ") + " (bind to 127.0.0.1 only)") }
    }
    foreach ($df in $dockerfiles) {
        $rel = Get-RelPath $df.FullName $Root
        $lines.Add("Dockerfile: $rel")
        $exposed = @(Select-String -Path $df.FullName -Pattern '^\s*EXPOSE\s+(\d+)' -ErrorAction SilentlyContinue |
            ForEach-Object { $_.Matches[0].Groups[1].Value })
        if ($exposed.Count -gt 0) { $lines.Add("  EXPOSE: " + ($exposed -join ", ")) }
        $lines.Add('  Try: docker build -t bb-scan-target -f "' + $df.FullName + '" "' + $Root + '" ; docker run --rm -p 127.0.0.1:8080:<EXPOSE_PORT> bb-scan-target')
    }
    return ($lines -join "`n")
}

# ==================================================================================================
if ($RepoUrl -notmatch '^https://(github\.com|gitlab\.com)/[\w.-]+(/[\w.-]+){1,4}(\.git)?/?$') {
    throw "Only plain https://github.com/owner/repo or https://gitlab.com/group/project URLs are allowed."
}
Test-Ollama

$repoName = ($RepoUrl.TrimEnd("/") -replace '\.git$', '').Split("/")[-1]
$dest = Join-Path $WorkDir $repoName
if (-not (Test-Path $dest)) {
    Write-Step "Cloning $RepoUrl"
    New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
    $old = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & git clone --depth 1 $RepoUrl $dest 2>&1 | Out-Host
    $ErrorActionPreference = $old
    if ($LASTEXITCODE -ne 0) { throw "git clone failed." }
} else {
    Write-Step "Using existing clone at $dest"
}
New-Item -ItemType Directory -Force -Path $ReportDir | Out-Null
$destFull = (Resolve-Path $dest).Path
$script:RepoRoot = $destFull

$commit = "unknown"
try {
    $old = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $sha = @(& git -C $dest rev-parse HEAD 2>$null)
    $ErrorActionPreference = $old
    if ($sha.Count -gt 0 -and $sha[0]) { $commit = [string]$sha[0] }
} catch { }
$semgrepVersion = Get-SemgrepVersion
$runDate = (Get-Date).ToString("yyyy-MM-dd HH:mm")

$dirNames = @($ExcludePaths | Where-Object { $_ -notmatch '[\*\.]' } | ForEach-Object { [regex]::Escape($_) })
$excludeRegex = '\\(node_modules|' + ($dirNames -join '|') + ')\\'

$histFile = Join-Path $WorkDir "_rule-history.jsonl"
if (-not $NoRuleCaps) {
    try {
        $script:RuleCaps = Get-RuleCaps $histFile
        if ($script:RuleCaps.Count -gt 0) {
            Write-Step ("Auto-caps loaded: {0} rule(s)" -f $script:RuleCaps.Count)
        }
    } catch { Write-Warning "Rule caps not loaded: $($_.Exception.Message)" }
}

$configs = New-Object System.Collections.Generic.List[string]
foreach ($c in $SemgrepConfigs) { $configs.Add($c) }
$extCounts = @(Get-ChildItem -Path $destFull -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch $excludeRegex } |
    Group-Object Extension)
if (-not $NoAutoLanguageRules) {
    foreach ($g in $extCounts) {
        $ext = $g.Name.ToLower()
        if ($LangRules.ContainsKey($ext) -and -not $configs.Contains($LangRules[$ext])) { $configs.Add($LangRules[$ext]) }
    }
}
$typeInfo = Get-RepoTypeInfo $destFull $extCounts $excludeRegex $RepoType
$repoType = $typeInfo.Type
$spec = Get-AttackerSpec $repoType
$script:RepoTypeName = $repoType
$script:AttackerOptions = $spec.Options
$script:AttackerList = @($spec.Options -split '\|')
$script:Outside = $spec.Outside
$script:AttackerGuidance = $spec.Guidance
$script:RouteCount = $typeInfo.Routes
if ($repoType -eq "infra") {
    foreach ($c in @("p/terraform", "p/kubernetes", "p/dockerfile")) { if (-not $configs.Contains($c)) { $configs.Add($c) } }
}
Write-Step ("Repo type: {0} ({1})" -f $repoType, $typeInfo.Evidence)
$dockerInfo = $null
if (-not $SkipDockerDetect) { try { $dockerInfo = Get-DockerRunInfo $destFull } catch { Write-Warning "Docker detection failed: $($_.Exception.Message)" } }
Write-Step ("Rulesets: " + ($configs -join ", "))

$raw = @()
foreach ($cfg in $configs) {
    $safe = ($cfg -replace '[^\w]', '_')
    $out = Join-Path $ReportDir "$repoName.semgrep.$safe.json"
    Write-Step "Semgrep: $cfg"
    if (-not (Invoke-SemgrepConfig $cfg $destFull $out)) { continue }
    try {
        $j = Get-Content $out -Raw -Encoding UTF8 | ConvertFrom-Json
        $raw += @($j.results)
        Write-Host ("    {0} finding(s)" -f @($j.results).Count)
    } catch { Write-Warning "Could not parse $out" }
}
$sevOrder = @{ ERROR = 0; WARNING = 1; INFO = 2 }
$raw = @($raw | Sort-Object `
    { if ([string]$_.check_id -match $CiHygieneRx) { 1 } else { 0 } }, `
    { $s = [string]$_.extra.severity; if ($sevOrder.ContainsKey($s)) { $sevOrder[$s] } else { 3 } })
Write-Step ("Total Semgrep findings: {0}" -f $raw.Count)

if ($UseCodeQL) {
    if (-not (Test-CodeQLCli)) {
        Write-Warning "CodeQL CLI not found on PATH. Install it from https://github.com/github/codeql-action/releases (or the CodeQL VS Code extension, which bundles the CLI) and add it to PATH. Skipping CodeQL for this run."
    } else {
        $cqLang = if ($CodeQLLanguage -ne "auto") { $CodeQLLanguage } else { Get-CodeQLLanguage $extCounts }
        if (-not $cqLang) {
            Write-Warning "Could not determine a CodeQL-supported language for this repo. Skipping CodeQL analysis."
        } elseif ($cqLang -notin @("javascript", "python")) {
            Write-Warning "Auto database build in this script only covers javascript/typescript and python. '$cqLang' usually needs its real build command (maven/gradle, msbuild, cmake, go build) via a manual codeql database create --command=... Skipping; run CodeQL by hand for this repo if you want its results, then pass the SARIF through ConvertFrom-CodeQLSarif."
        } else {
            $sarif = Invoke-CodeQLScan $destFull $WorkDir $repoName $ReportDir $cqLang $CodeQLSuite
            if ($sarif) {
                $cqResults = @(ConvertFrom-CodeQLSarif $sarif $destFull)
                $cqResults = @($cqResults | Select-Object -First $MaxCodeQLLeads)
                Write-Step ("CodeQL findings: {0} (capped at {1})" -f $cqResults.Count, $MaxCodeQLLeads)
                $raw += $cqResults
            }
        }
    }
}

$leads = New-Object System.Collections.ArrayList
$seen = @{}
$groupInfo = @{}
$pathCache = @{}
$lineCache = @{}
$overCap = 0
foreach ($r in $raw) {
    $p = [string]$r.path
    if (-not $pathCache.ContainsKey($p)) {
        $rp = Resolve-Path -LiteralPath $p -ErrorAction SilentlyContinue
        if ($rp) { $pathCache[$p] = $rp.Path } else { $pathCache[$p] = "" }
    }
    $fullPath = $pathCache[$p]
    if (-not $fullPath) { continue }
    $line = [int]$r.start.line
    $dk = "$fullPath|$line"
    if ($seen.ContainsKey($dk)) {
        $prev = $seen[$dk]
        if ($prev -is [pscustomobject]) { $prev.Hint += " | also: $($r.check_id)" }
        continue
    }
    $gk = "$($r.check_id)|$fullPath"
    if (-not $groupInfo.ContainsKey($gk)) { $groupInfo[$gk] = @{ Hits = 0; LineNums = (New-Object System.Collections.Generic.List[int]) } }
    $groupInfo[$gk].Hits++
    $groupInfo[$gk].LineNums.Add($line)
    if ($groupInfo[$gk].Hits -gt $MaxPerGroup) { $seen[$dk] = $false; continue }
    if ($leads.Count -ge $MaxLeads) { $seen[$dk] = $false; $overCap++; continue }

    if (-not $lineCache.ContainsKey($fullPath)) {
        $txt = [string](Get-Content -LiteralPath $fullPath -Raw -Encoding UTF8)
        $lineCache[$fullPath] = [pscustomobject]@{ Text = $txt; Lines = @(Get-Content -LiteralPath $fullPath -Encoding UTF8) }
    }
    $fc = $lineCache[$fullPath]
    $rel = Get-RelPath $fullPath $destFull
    $tags = Get-Tags $rel
    if ($repoType -eq "cli_desktop" -and $fc.Text -match $PrivRx) { $tags += "privileged" }
    $ctx = Get-Context $fc.Lines $line ([int]$r.end.line)
    $limit = 4
    if ($ctx.Sig -match '(?i)env|token|secret|credential|config|world|key|url|path|host') { $limit = 10 }
    $callersAll = @(Get-Callers $destFull $ctx.Name $fullPath $excludeRegex $limit)
    $ciCtx = $null
    $ciSummary = ""
    if ($tags -contains "ci") {
        $ciCtx = Get-CiContext $fc.Lines $line
        $ciSummary = $ciCtx.Summary
    }
    $callerLines = ($callersAll -join "`n")
    $lead = [pscustomobject]@{
        Id = ("{0}@{1}:{2}" -f $r.check_id, (Split-Path $fullPath -Leaf), $line)
        Kind = "semgrep"; RuleId = [string]$r.check_id; GroupKey = $gk
        File = $fullPath; Rel = $rel; Tags = $tags; Line = $line
        Hint = $(if ([string]$r.check_id -match '^codeql-') { "CodeQL rule $($r.check_id): $($r.extra.message)" } else { "Semgrep rule $($r.check_id): $($r.extra.message)" })
        Engine = $(if ($r.PSObject.Properties["Engine"]) { [string]$r.Engine } else { "semgrep" })
        Snippet = $ctx.Snippet
        Callers = @($callersAll | Select-Object -First 4); CallersAll = $callersAll
        Hay = (Normalize-Text $fc.Text) + " " + (Normalize-Text ($ctx.Snippet -replace '(?m)^\s*\d+:\s?', '')) + " " + (Normalize-Text $callerLines) + " " + (Normalize-Text (($(if ($r.PSObject.Properties["CqLines"]) { $r.CqLines -join " " } else { "" }))))
        Ci = $ciCtx; CiSummary = $ciSummary; Pre = $null; Dropped = $false; DropWhy = ""
    }
    $seen[$dk] = $lead
    [void]$leads.Add($lead)
}
if ($overCap -gt 0) { Write-Warning "$overCap additional finding(s) beyond -MaxLeads were not triaged." }

$surfaceRan = $false
if (-not $SkipSurfaceMap -and ($repoType -eq "service" -or $ForceSurface)) {
    $surfaceRan = $true
    Write-Step "Mapping attack surface (routes without a visible auth check)"
    $mapFile = Join-Path $ReportDir "$repoName.attack-surface.md"
    $surface = Get-SurfaceLeads $destFull $destFull $excludeRegex $MaxSurfaceLeads $mapFile
    foreach ($s in $surface) {
        $rel = Get-RelPath $s.Path $destFull
        $sid = ("surface-authz@{0}:{1}" -f (Split-Path $s.Path -Leaf), $s.Line)
        $lead = [pscustomobject]@{
            Id = $sid; Kind = "surface"; RuleId = "surface-authz"; GroupKey = $sid
            File = $s.Path; Rel = $rel; Tags = $s.Tags; Line = [int]$s.Line
            Hint = "Route handler uses attacker-supplied identifiers and shows no auth or ownership check (possible missing authorization or IDOR). Auth may be enforced elsewhere."
            Snippet = $s.Snippet; Callers = @(); CallersAll = @()
            Hay = (Normalize-Text $s.Text) + " " + (Normalize-Text ($s.Snippet -replace '(?m)^\s*\d+:\s?', ''))
            Ci = $null; CiSummary = ""; Pre = $null; Dropped = $false; DropWhy = ""
        }
        $groupInfo[$sid] = @{ Hits = 1; LineNums = (New-Object System.Collections.Generic.List[int]) }
        $groupInfo[$sid].LineNums.Add([int]$s.Line)
        [void]$leads.Add($lead)
    }
    Write-Host ("    route-like entry points: {0}; surface leads: {1}" -f $script:RouteCount, @($surface).Count)
}
if ($repoType -eq "cli_desktop" -or $repoType -eq "vscode_extension" -or $ForceLocalChecks) {
    Write-Step "Local checks for repo type $repoType"
    $localLeads = @(Get-LocalLeads $destFull $destFull $excludeRegex $MaxLocalLeads $repoType)
    foreach ($s in $localLeads) {
        $rel = Get-RelPath $s.Path $destFull
        $tags = Get-Tags $rel
        if ($s.Text -match $PrivRx) { $tags += "privileged" }
        $lid = ("{0}@{1}:{2}" -f $s.Rule, (Split-Path $s.Path -Leaf), $s.Line)
        $lgk = ("{0}|{1}" -f $s.Rule, $s.Path)
        $lead = [pscustomobject]@{
            Id = $lid; Kind = "local"; RuleId = [string]$s.Rule; GroupKey = $lgk
            File = $s.Path; Rel = $rel; Tags = $tags; Line = [int]$s.Line
            Hint = "Local check $($s.Rule): $($s.Hint)"
            Snippet = $s.Snippet; Callers = @(); CallersAll = @()
            Hay = (Normalize-Text $s.Text) + " " + (Normalize-Text ($s.Snippet -replace '(?m)^\s*\d+:\s?', ''))
            Ci = $null; CiSummary = ""; Pre = $null; Dropped = $false; DropWhy = ""
        }
        if (-not $groupInfo.ContainsKey($lgk)) {
            $groupInfo[$lgk] = @{ Hits = [int]$s.GroupHits; LineNums = (New-Object System.Collections.Generic.List[int]) }
            foreach ($x in $s.GroupLines) { $groupInfo[$lgk].LineNums.Add([int]$x) }
        }
        [void]$leads.Add($lead)
    }
    Write-Host ("    local-check leads: {0}" -f @($localLeads).Count)
}
if ($leads.Count -eq 0) { Write-Step "No leads to triage."; return }

foreach ($lead in $leads) { $lead.Pre = Get-PreVerdict $lead }
if ($UseFastFilter) {
    Write-Step "Tier 1: fast filter with $FastModel"
    foreach ($lead in $leads) {
        if ($lead.Kind -ne "semgrep" -or $lead.Pre -or $lead.Ci) { continue }
        if (-not (Get-Playbook $lead).Flow) { continue }
        if ($lead.RuleId -match 'xss|html|script-tag|innerhtml|dangerously') { continue }
        try {
            $t1 = Test-Fast $lead.Snippet
            if ($t1 -and $t1.relevant -eq $false) { $lead.Dropped = $true; $lead.DropWhy = [string]$t1.reason }
        } catch { Write-Warning "Fast filter failed for $($lead.Id): $($_.Exception.Message)" }
    }
}

Write-Step "Tier 2: triage with $DeepModel"
$cacheDir = Join-Path $WorkDir "_cache"
New-Item -ItemType Directory -Force -Path $cacheDir | Out-Null
$leadById = @{}
$results = @()
$i = 0
foreach ($lead in $leads) {
    $i++
    $leadById[$lead.Id] = $lead
    try {
        if ($lead.Pre) { Set-Score $lead.Pre $lead; $results += $lead.Pre; Write-Host ("[{0}/{1}] rule    {2}" -f $i, $leads.Count, $lead.Id); continue }
        if ($lead.Dropped) { $res = New-Result $lead @{ verdict = "dropped_by_fast_filter"; why = $lead.DropWhy }; $results += $res; continue }
        $key = Get-Sha ($ScriptVersion + $CacheVersion + $lead.Snippet + $lead.Hint + $DeepModel + $lead.CiSummary + ($lead.Callers -join "|"))
        $cacheFile = Join-Path $cacheDir "$key.json"
        if (Test-Path $cacheFile) { $results += (Get-Content $cacheFile -Raw -Encoding UTF8 | ConvertFrom-Json); Write-Host ("[{0}/{1}] cached  {2}" -f $i, $leads.Count, $lead.Id); continue }
        Write-Host ("[{0}/{1}] triage  {2}" -f $i, $leads.Count, $lead.Id)
        $res = Resolve-Result $lead (Test-Deep $lead)
        Set-Score $res $lead
        $res | ConvertTo-Json -Depth 4 | Set-Content -Path $cacheFile -Encoding UTF8
        $results += $res
    } catch {
        Write-Warning "Triage failed for $($lead.Id): $($_.Exception.Message)"
        $results += (New-Result $lead @{ why = "Triage error: $($_.Exception.Message)" })
    }
}

if (-not $NoAutoResolve) {
    $needsResolve = @($results | Where-Object {
            $_.missing_context -and
            ($_.verdict -eq "unverified" -or $_.verdict -eq "interesting" -or $_.verdict -eq "suspicious" -or $_.verdict -eq "potential_vuln")
        })
    if ($needsResolve.Count -gt 0) {
        Write-Step ("Auto-resolving missing context for {0} lead(s)" -f $needsResolve.Count)
        $resolved = New-Object System.Collections.ArrayList
        foreach ($r in $results) {
            $match = $needsResolve | Where-Object { $_.id -eq $r.id } | Select-Object -First 1
            if (-not $match) { [void]$resolved.Add($r); continue }
            $l = $leadById[$r.id]
            if (-not $l) { [void]$resolved.Add($r); continue }
            $defs = @()
            $candidates = Get-MissingContextCandidates ([string]$r.missing_context) $l.Hay 3
            foreach ($candidate in $candidates) {
                $defs += (Get-Definition $destFull $candidate $excludeRegex 2)
                $defs += (Get-Assignment $destFull $candidate $excludeRegex 2)
            }
            if ($defs.Count -eq 0) {
                $tried = if ($candidates.Count -gt 0) { $candidates -join ", " } else { "(no code-shaped identifier found in missing_context)" }
                $r.why += " [auto-resolve: no definitions or assignments found for: $tried]"
                [void]$resolved.Add($r); continue
            }
            $extra = ($defs -join "`n`n")
            $l2 = $l.PSObject.Copy()
            $l2.Snippet = $l.Snippet + "`n`n// ---- definitions referenced in missing_context ----`n" + $extra
            $l2.Hay = $l.Hay + " " + (Normalize-Text $extra)
            $key2 = Get-Sha ($ScriptVersion + $CacheVersion + $l2.Snippet + $l2.Hint + $DeepModel + $l2.CiSummary + "|resolved")
            $cacheFile2 = Join-Path $cacheDir "$key2.json"
            if (Test-Path $cacheFile2) { $r2 = (Get-Content $cacheFile2 -Raw -Encoding UTF8 | ConvertFrom-Json); Write-Host ("   cached   {0}" -f $r.id) }
            else {
                Write-Host ("   resolve  {0}" -f $r.id)
                try { $r2 = Resolve-Result $l2 (Test-Deep $l2); Set-Score $r2 $l2; $r2 | ConvertTo-Json -Depth 4 | Set-Content -Path $cacheFile2 -Encoding UTF8 }
                catch { Write-Warning "Re-prompt failed for $($r.id): $($_.Exception.Message)"; $r2 = $r }
            }
            [void]$resolved.Add($r2)
        }
        $results = @($resolved)
    }
}

$vRank = @{ potential_vuln = 0; suspicious = 1; interesting = 2; unverified = 3; not_vuln = 4; dropped_by_fast_filter = 5; filtered_by_tag = 6 }
$byGroup = @{}
foreach ($r in $results) {
    $l = $leadById[$r.id]
    $gk = $r.id
    if ($l) { $gk = $l.GroupKey }
    if (-not $byGroup.ContainsKey($gk)) { $byGroup[$gk] = New-Object System.Collections.ArrayList }
    [void]$byGroup[$gk].Add($r)
}
$groupRows = @()
foreach ($gk in $byGroup.Keys) {
    $items = @($byGroup[$gk])
    $best = $items | Sort-Object @{ Expression = { [double]$_.score }; Descending = $true }, @{ Expression = { Get-Weight $vRank ([string]$_.verdict) 9 } } | Select-Object -First 1
    $count = $items.Count
    $lineText = [string]$best.line
    if ($groupInfo.ContainsKey($gk)) {
        $count = $groupInfo[$gk].Hits
        $ls = @($groupInfo[$gk].LineNums | Sort-Object)
        if ($ls.Count -le 6) { $lineText = ($ls -join ", ") } else { $lineText = ("{0}-{1}" -f $ls[0], $ls[$ls.Count - 1]) }
    }
    $groupRows += [pscustomobject]@{ Key = $gk; Best = $best; Count = $count; Lines = $lineText; Score = [double]$best.score; Rank = (Get-Weight $vRank ([string]$best.verdict) 9) }
}
$groupRows = @($groupRows | Sort-Object @{ Expression = { $_.Score }; Descending = $true }, @{ Expression = { $_.Rank } })

$ruleHist = @()
try { $ruleHist = Update-RuleHistory $histFile $results $repoName $commit $repoType } catch { Write-Warning "Rule history not updated" }

$jsonOut = Join-Path $ReportDir "$repoName.triage.json"
$mdOut = Join-Path $ReportDir "$repoName.triage.md"
$secondOut = Join-Path $ReportDir "$repoName.second-opinion.md"
ConvertTo-Json -InputObject @($results) -Depth 4 | Set-Content -Path $jsonOut -Encoding UTF8

$countBy = @{}
foreach ($r in $results) { $v = [string]$r.verdict; if ($countBy.ContainsKey($v)) { $countBy[$v]++ } else { $countBy[$v] = 1 } }
$langSummary = (@($extCounts | Where-Object { $LangRules.ContainsKey($_.Name.ToLower()) } | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { "{0} ({1})" -f $_.Name, $_.Count }) -join ", ")
$tagCounts = @{}
foreach ($l in $leads) { foreach ($t in $l.Tags) { if ($tagCounts.ContainsKey($t)) { $tagCounts[$t]++ } else { $tagCounts[$t] = 1 } } }
$tagSummary = (($tagCounts.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { "{0}: {1}" -f $_.Key, $_.Value }) -join ", ")
$worth = @($groupRows | Where-Object { ($_.Best.verdict -eq "potential_vuln" -or $_.Best.verdict -eq "suspicious") -and $_.Best.confidence -eq "likely" } | Select-Object -First 3)

$md = New-Object System.Collections.Generic.List[string]
$md.Add("# Triage report: $repoName")
$md.Add("")
$md.Add("- Repository: $RepoUrl")
$md.Add("- Commit: $commit")
$md.Add("- Date: $runDate")
$md.Add("- Tool: $ScriptVersion, Semgrep $semgrepVersion")
$md.Add("- Rulesets: $($configs -join ', ')")
$md.Add("- Models: deep=$DeepModel" + $(if ($UseFastFilter) { ", fast=$FastModel" } else { "" }))
$md.Add("")
$md.Add("**Every item is a lead, not a finding.**")
$md.Add("")
$md.Add("## Summary (generated by the script, not by the model)")
$md.Add("")
$md.Add("- Repo type: $repoType ($($typeInfo.Evidence))")
$md.Add("- Outside attackers considered: $($script:Outside -join ', ')")
$md.Add("- Main languages: $langSummary")
$md.Add("- Route-like entry points found: $($script:RouteCount)")
$md.Add("- Leads triaged: $($leads.Count) in $($groupRows.Count) groups; tags: $tagSummary")
$engineCounts = @{}
foreach ($l in $leads) { $e = $(if ($l.Engine) { $l.Engine } else { "semgrep" }); if ($engineCounts.ContainsKey($e)) { $engineCounts[$e]++ } else { $engineCounts[$e] = 1 } }
if ($engineCounts.ContainsKey("codeql")) { $md.Add("- Engines: " + (($engineCounts.GetEnumerator() | ForEach-Object { "{0}: {1}" -f $_.Key, $_.Value }) -join ", ")) }
$verdictLine = (($countBy.GetEnumerator() | Sort-Object Name | ForEach-Object { "{0}: {1}" -f $_.Key, $_.Value }) -join ", ")
$md.Add("- Verdicts: $verdictLine")
if ($script:RuleCaps.Count -gt 0) { $md.Add("- Auto-capped rules: $(($script:RuleCaps.Keys) -join ', ')") }
$md.Add("")
if ($worth.Count -gt 0) {
    $md.Add("Worth an hour of your time first:")
    foreach ($w in $worth) { $md.Add(("- {0} ({1} impact, {2} exploitability): {3}" -f $w.Best.id, $w.Best.impact, $w.Best.exploitability, $w.Best.why)) }
} else {
    $md.Add("No lead cleared the bar. Read the attack-surface map and the top suspicious items yourself; a quiet scan is a valid result.")
}
$md.Add("")
if ($dockerInfo) {
    $md.Add("## Dynamic validation")
    $md.Add("")
    $md.Add("For confirming a specific lead below, not for scanning. Bind only to 127.0.0.1.")
    $md.Add("")
    $md.Add($dockerInfo)
    $md.Add("")
    $md.Add("Once the target is running locally, use a proxy (Burp, Caido) or a raw client to send a crafted request that exercises the lead, following the entry point and validation notes in its Details section below.")
    $md.Add("")
}
$md.Add("## Ranked leads (grouped by rule and file)")
$md.Add("")
$md.Add("| # | Verdict | Impact | Exploitability | Confidence | Tags | Lead |")
$md.Add("|---|---|---|---|---|---|---|")
$n = 0
foreach ($g in $groupRows) {
    if ($g.Best.verdict -eq "filtered_by_tag") { continue }
    $n++
    if ($n -gt 40) { break }
    $b = $g.Best
    $leadCell = ("{0}@{1} ({2} instance(s), lines {3})" -f $b.rule, (Split-Path ([string]$b.file) -Leaf), $g.Count, $g.Lines)
    $md.Add(("| {0} | {1} | {2} | {3} | {4} | {5} | {6} |" -f $n, $b.verdict, $b.impact, $b.exploitability, $b.confidence, $b.tags, $leadCell))
}
$md.Add("")
$md.Add("## Details")
$md.Add("")
$detailRows = @($groupRows | Where-Object { $_.Best.verdict -eq "potential_vuln" -or $_.Best.verdict -eq "suspicious" } | Select-Object -First 15)
$detailRows += @($groupRows | Where-Object { $_.Best.verdict -eq "interesting" -and $_.Best.class -eq "signal" } | Select-Object -First 5)
foreach ($g in $detailRows) {
    $b = $g.Best
    $l = $leadById[$b.id]
    $md.Add("### $($b.id)")
    $md.Add("- Verdict: **$($b.verdict)**; impact $($b.impact), exploitability $($b.exploitability), confidence $($b.confidence); tags: $($b.tags)")
    $md.Add("- Location: $($b.file):$($b.line); $($g.Count) instance(s), lines $($g.Lines)")
    if ($b.ci) { $md.Add("- Workflow context: $($b.ci)") }
    $md.Add("- Attacker: $($b.attacker); entry point: $($b.entry_point)")
    $md.Add("- Validation seen: $($b.validation)")
    $md.Add("- Why: $($b.why)")
    $md.Add("- Missing context: $($b.missing_context)")
    $md.Add("- **Human next step:** $($b.to_verify)")
    if ($b.source) { $md.Add(""); $md.Add("Source:"); $md.Add('```'); $md.Add([string]$b.source); $md.Add('```') }
    if ($b.flow) { $md.Add("Flow:"); $md.Add('```'); $md.Add([string]$b.flow); $md.Add('```') }
    if ($b.sink) { $md.Add("Sink:"); $md.Add('```'); $md.Add([string]$b.sink); $md.Add('```') }
    if ($l -and $l.CallersAll.Count -gt 0) {
        $md.Add("Call sites:")
        $md.Add('```')
        foreach ($c in $l.CallersAll) { $md.Add([string]$c) }
        $md.Add('```')
    }
    $md.Add("")
}
$hyg = @($groupRows | Where-Object { $_.Best.class -eq "hygiene" })
if ($hyg.Count -gt 0) {
    $md.Add("## Hygiene items (low value, grouped)")
    $md.Add("")
    foreach ($g in $hyg) { $md.Add(("- {0}@{1}: {2} instance(s), lines {3}" -f $g.Best.rule, (Split-Path ([string]$g.Best.file) -Leaf), $g.Count, $g.Lines)) }
    $md.Add("")
}
$dead = @($groupRows | Where-Object { $_.Best.class -eq "dead_code" })
if ($dead.Count -gt 0) {
    $md.Add("## Dismissed as dead code")
    $md.Add("")
    foreach ($g in $dead) { $md.Add(("- {0}: {1}" -f $g.Best.id, $g.Best.why)) }
    $md.Add("")
}
if ($ruleHist.Count -gt 0) {
    $md.Add("## Rule history across your scans")
    $md.Add("")
    $md.Add("| Rule | Repos | Leads | Signal | Dismissed |")
    $md.Add("|---|---|---|---|---|")
    foreach ($h in $ruleHist) { $md.Add(("| {0} | {1} | {2} | {3} | {4} |" -f $h.rule, $h.repos, $h.leads, $h.signal, $h.dismissed)) }
    $md.Add("")
}
$md | Set-Content -Path $mdOut -Encoding UTF8

$so = New-Object System.Collections.Generic.List[string]
$so.Add("# Second-opinion pack: $repoName (commit $commit)")
$so.Add("")
$so.Add("Paste this into a stronger model. It contains public open-source code only.")
$so.Add("Detected repo type: $repoType. Attacker model used: $($script:AttackerGuidance)")
$so.Add("")
$so.Add("Task: First, from the README and file tree, describe what this project is and where its trust boundaries are. Then, for each lead, decide whether it is a real vulnerability reachable by an outside attacker. List what other code you would need to see, the realistic impact, and the cheapest proof-of-concept. Say plainly when a lead is a false positive.")
$so.Add("")
$readme = Get-ChildItem -Path $destFull -File -Filter "README*" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($readme) {
    $so.Add("## README (first 60 lines)")
    $so.Add('```')
    foreach ($ln in (Get-Content -LiteralPath $readme.FullName -TotalCount 60 -Encoding UTF8)) { $so.Add([string]$ln) }
    $so.Add('```')
    $so.Add("")
}
$so.Add("## Top-level layout")
$so.Add('```')
foreach ($d in (Get-ChildItem -Path $destFull -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne ".git" } | Select-Object -First 40)) {
    $so.Add($d.Name + "/")
    if ($d.Name -in @("packages", "apps")) {
        foreach ($sub in (Get-ChildItem -Path $d.FullName -Directory -ErrorAction SilentlyContinue | Select-Object -First 30)) { $so.Add("  " + $d.Name + "/" + $sub.Name + "/") }
    }
}
$so.Add('```')
$so.Add("")
$topGroups = @($groupRows | Where-Object {
        (@("potential_vuln", "suspicious", "interesting", "unverified") -contains [string]$_.Best.verdict) -and $_.Best.class -eq "signal"
    } | Sort-Object @{ Expression = { $_.Rank } }, @{ Expression = { $_.Score }; Descending = $true } | Select-Object -First $SecondOpinionCount)
foreach ($g in $topGroups) {
    $b = $g.Best
    $l = $leadById[$b.id]
    if (-not $l) { continue }
    $so.Add("## $($b.id)")
    $so.Add("Tags: $($b.tags). Local verdict: $($b.verdict).")
    $so.Add("Static analyzer hint: $($l.Hint)")
    $so.Add("Local model's note: $($b.why)")
    if ($b.ci) { $so.Add("Workflow context: $($b.ci)") }
    $so.Add("Location: $($b.file):$($b.line)")
    $so.Add('```')
    $so.Add($l.Snippet)
    $so.Add('```')
    if ($l.CallersAll.Count -gt 0) { $so.Add("Callers:"); $so.Add('```'); foreach ($c in $l.CallersAll) { $so.Add([string]$c) }; $so.Add('```') }
    if ($b.missing_context) {
        $inlineDefs = @()
        foreach ($candidate in (Get-MissingContextCandidates ([string]$b.missing_context) $l.Hay 3)) {
            $inlineDefs += (Get-Definition $destFull $candidate $excludeRegex 1)
            $inlineDefs += (Get-Assignment $destFull $candidate $excludeRegex 1)
        }
        if ($inlineDefs.Count -gt 0) {
            $so.Add("Definitions referenced in missing_context:")
            foreach ($d in $inlineDefs) { $so.Add('```'); $so.Add($d); $so.Add('```') }
        }
    }
    $so.Add("")
}
if ($topGroups.Count -eq 0) { $so.Add("No signal leads were produced for this repo, so there is nothing to review here.") }
$so | Set-Content -Path $secondOut -Encoding UTF8

Write-Step "Done"
Write-Host "Report:          $mdOut"
Write-Host "JSON:            $jsonOut"
Write-Host "Second opinion:  $secondOut"
if ($surfaceRan) { Write-Host ("Attack surface:  " + (Join-Path $ReportDir "$repoName.attack-surface.md")) }
Write-Host ("Verdicts: " + $verdictLine)
if ($script:RuleCaps.Count -gt 0) { Write-Host ("Rule caps active: {0}" -f $script:RuleCaps.Count) }