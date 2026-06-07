# Contributing

## Adding New Tools

Adding a tool to ModTester requires **one Python function** and **one registry entry**. The LLM can use it immediately with no retraining or fine-tuning.

## Step-by-Step

### 1. Create the Tool Function

Add your function to an existing file in `tools/` or create a new module.

```python
# tools/my_tools.py
import subprocess
import shlex

def my_new_scanner(target: str, options: str = "") -> str:
    """Run my-scanner against a target."""
    cmd = f"my-scanner {shlex.quote(target)}"
    if options:
        cmd += f" {shlex.quote(options)}"
    
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=300
        )
        return (result.stdout + result.stderr).strip() or "No results"
    except subprocess.TimeoutExpired:
        return "Scan timed out"
    except Exception as e:
        return f"Error: {e}"
```

**Rules:**
- Function must return a **string** (the tool output)
- Use `shlex.quote()` for all user-provided values (prevents command injection)
- Set a reasonable `timeout`
- Handle errors gracefully (never raise exceptions)

### 2. Register in `tools/__init__.py`

```python
# Add import
from .my_tools import my_new_scanner

# Add to TOOL_REGISTRY
TOOL_REGISTRY["my_new_scanner"] = {
    "fn": my_new_scanner,
    "category": "vulnerability",
    "description": "Scans target for XYZ vulnerabilities with detailed output.",
    "schema": {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "URL or IP to scan"},
            "options": {"type": "string", "description": "Additional scanner flags"},
        },
        "required": ["target"],
    },
}
```

**Schema tips:**
- The `description` field is what the AI reads to decide when to use your tool
- Be specific. "Scans for XSS in JavaScript-rendered pages" is better than "Web scanner"
- Mark truly required params in `required`; AI will provide them

### 3. Add Display Message (Optional)

In `tools/display.py`, add an action message:

```python
TOOL_ACTION_MESSAGES["my_new_scanner"] = lambda a: f"Scanning {_safe(a, 'target')} for XYZ vulnerabilities..."
```

### 4. Test

```bash
# Start server
python server.py

# Test directly
curl -X POST http://localhost:8000/mcp/v1/tools/my_new_scanner \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'

# Test via AI
python client.py "Scan example.com with the XYZ scanner"
```

## Best Practices

- **One tool = one purpose.** Don't combine scanning + exploitation in one function.
- **Return structured text.** The AI reads and interprets the output.
- **Truncate large outputs.** Cap at 10,000 chars to avoid overwhelming the LLM context.
- **Use timeouts.** A hung tool blocks the entire chain.
- **Validate inputs.** Don't trust the AI to always provide perfect arguments.
- **Never hardcode credentials.** Use environment variables.

## Tool Categories

| Category | When to use |
|----------|-------------|
| `recon` | Information gathering without touching target |
| `network` | Port/service scanning |
| `web` | HTTP-based discovery and testing |
| `vulnerability` | Detecting specific vulnerability classes |
| `exploitation` | Confirming and exploiting vulnerabilities |
| `verification` | Proving a vulnerability with evidence |
| `post-exploitation` | Actions after gaining access |
| `reporting` | Recording and generating findings |

## Example: Adding a Custom Nuclei Template Scanner

```python
def nuclei_custom(target: str, template_path: str) -> str:
    """Run nuclei with a custom template directory."""
    cmd = f"nuclei -u {shlex.quote(target)} -t {shlex.quote(template_path)} -silent -nc"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
        return result.stdout.strip() or "No findings"
    except Exception as e:
        return f"Error: {e}"
```

The AI will automatically use this when it determines custom templates are appropriate, based on the description you provide in the registry.
