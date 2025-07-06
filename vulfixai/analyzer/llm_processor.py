import os
import json
from dotenv import load_dotenv
import ollama 
import logging
import traceback

logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s') 

load_dotenv()

OLLAMA_MODEL_NAME = "gemma3:1b"
logging.info(f"Configured to use Ollama model: {OLLAMA_MODEL_NAME}")


# Centralized Constants 
MAX_PACKAGE_JSON_SEARCH_DEPTH = 3
CODE_SNIPPET_CONTEXT_LINES = 3 # Lines above/below the vulnerable code to include
MANIFEST_FILES = ['package.json', 'package-lock.json', 'pom.xml', 'requirements.txt', 'go.mod', 'Gemfile.lock', 'yarn.lock', 'composer.lock', 'Cargo.lock']


def _get_package_json_path(repo_root_path):
    """
    Attempts to find package.json within the repository root or its subdirectories.
    Searches recursively up to MAX_PACKAGE_JSON_SEARCH_DEPTH (centralized constant).
    """
    if not repo_root_path or not os.path.isdir(repo_root_path):
        logging.debug(f"Invalid repo_root_path provided for package.json search: {repo_root_path}")
        return None

    for root, dirs, files in os.walk(repo_root_path):
        # Calculate current depth from the initial repo_root_path
        current_depth = root[len(repo_root_path):].count(os.sep)
        if current_depth > MAX_PACKAGE_JSON_SEARCH_DEPTH:
            # Skip traversing deeper directories
            del dirs[:] # This modifies 'dirs' in-place, stopping os.walk from going deeper
            continue

        if 'package.json' in files:
            package_json_full_path = os.path.join(root, 'package.json')
            logging.debug(f"Found package.json at: {package_json_full_path}")
            return package_json_full_path
    
    logging.debug(f"No package.json found within {repo_root_path} (searched up to depth {MAX_PACKAGE_JSON_SEARCH_DEPTH}).")
    return None

def _is_dev_dependency(repo_root_path, pkg_name):
    """
    Checks if a given package name is listed in devDependencies in package.json.
    Assumes repo_root_path is the base directory to start searching for package.json.
    Handles scoped packages like @babel/core correctly.
    """
    package_json_path = _get_package_json_path(repo_root_path)
    if not package_json_path:
        logging.debug(f"Cannot check dev dependency for {pkg_name}: No package.json found in {repo_root_path}.")
        return False 

    try:
        with open(package_json_path, 'r', encoding='utf-8') as f:
            package_data = json.load(f)
        
        dev_dependencies = package_data.get('devDependencies', {})
        dependencies = package_data.get('dependencies', {})

        # Checks if it's explicitly in devDependencies
        if pkg_name in dev_dependencies:
            logging.debug(f"{pkg_name} found in devDependencies of {package_json_path}.")
            return True
        # If it's in dependencies, it's NOT a dev dependency
        elif pkg_name in dependencies:
            logging.debug(f"{pkg_name} found in dependencies of {package_json_path}.")
            return False
        else:
            logging.debug(f"{pkg_name} not found in top-level dependencies or devDependencies of {package_json_path}.")
            return False 

    except json.JSONDecodeError as e:
        logging.warning(f"Could not decode package.json at {package_json_path}: {e}")
        return False 
    except Exception as e:
        logging.warning(f"An unexpected error occurred reading package.json at {package_json_path}: {e}")
        return False


def load_and_parse_trivy_report(report_path):
    """
    Loads a Trivy JSON report and extracts relevant vulnerability information,
    including file paths and line numbers if available.
    """
    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            report_data = json.load(f)
    except FileNotFoundError:
        logging.error(f"Report file not found at {report_path}")
        return None
    except json.JSONDecodeError:
        logging.error(f"Could not decode JSON from {report_path}. Is it a valid JSON file?")
        return None

    vulnerabilities = []
    if "Results" in report_data:
        for result in report_data["Results"]:
            if "Vulnerabilities" in result:
                for vuln in result["Vulnerabilities"]:
                    file_path = None
                    start_line = None
                    end_line = None

                    # FilePath extraction based on common Trivy output
                    if "Location" in vuln and "FilePath" in vuln["Location"]:
                        file_path = vuln["Location"].get("FilePath")
                        start_line = vuln["Location"].get("StartLine")
                        end_line = vuln["Location"].get("EndLine")
                    elif "Resource" in vuln and "FilePath" in vuln["Resource"]:
                        # For some types, 'Resource' might contain the path
                        file_path = vuln["Resource"].get("FilePath")
                        start_line = vuln["Resource"].get("StartLine")
                        end_line = vuln["Resource"].get("EndLine")
                    elif result.get("Target"): # Fallback for manifest files like package-lock.json
                        if result.get("Type") in ["npm", "bundler", "composer", "pip", "gobinary", "golang", "java", "maven", "nuget", "apk", "dpkg", "rpm", "gem", "python-pkg", "rust-binary", "cargo"]:
                            file_path = result.get("Target") # often the manifest file path
                        elif result.get("Type") in ["filesystem", "secret", "config"] and result.get("Target"):
                            file_path = result.get("Target") # specific file path

                    vulnerabilities.append({
                        "Target": result.get("Target"), # Original target (e.g., manifest file path)
                        "Type": result.get("Type"),
                        "VulnerabilityID": vuln.get("VulnerabilityID"),
                        "PkgName": vuln.get("PkgName"),
                        "InstalledVersion": vuln.get("InstalledVersion"),
                        "FixedVersion": vuln.get("FixedVersion", 'N/A'),
                        "Severity": vuln.get("Severity"),
                        "Title": vuln.get("Title"),
                        "Description": vuln.get("Description"),
                        "PrimaryURL": vuln.get("PrimaryURL"),
                        "CweIDs": vuln.get("CweIDs", []),
                        "FilePath": file_path, # This is the path relative to the scanned root
                        "StartLine": start_line,
                        "EndLine": end_line
                    })
    return vulnerabilities


def read_code_snippet(file_path, start_line, end_line):
    """
    Reads a specific code snippet from a file with optional context lines.
    Assumes file_path is relative to the current working directory (cloned repo root).
    Returns the snippet as a string or None if file not found/error or if it's
    a manifest file without specific line numbers.
    """
    
    # Check if the path indicates a manifest file where a code snippet isn't meaningful
    if file_path and any(manifest in file_path.lower() for manifest in MANIFEST_FILES) and (start_line is None or end_line is None):
        logging.debug(f"Skipping code snippet for manifest file: {file_path} (no specific lines).")
        return None

    # Construct the full path using the current working directory (which is the cloned repo root)
    full_file_path = os.path.join(os.getcwd(), file_path) 

    if not os.path.exists(full_file_path):
        logging.debug(f"File not found for snippet at: {full_file_path}")
        return None

    try:
        with open(full_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        if not lines:
            return None

        # Adjust for 0-based indexing for list access
        actual_start_line = max(0, (start_line or 1) - 1)
        actual_end_line = (end_line or actual_start_line + 1) - 1

        # Calculate snippet boundaries with context, using centralized CODE_SNIPPET_CONTEXT_LINES
        snippet_start = max(0, actual_start_line - CODE_SNIPPET_CONTEXT_LINES) 
        snippet_end = min(len(lines), actual_end_line + CODE_SNIPPET_CONTEXT_LINES + 1)

        snippet_lines = lines[snippet_start:snippet_end]

        formatted_snippet = []
        for i, line_content in enumerate(snippet_lines):
            line_num = snippet_start + i + 1
            is_vulnerable_line = (start_line is not None and end_line is not None and
                                  line_num >= start_line and line_num <= end_line)
            marker = ">>" if is_vulnerable_line else "  "
            formatted_snippet.append(f"{marker} {line_num:4d} | {line_content.rstrip()}")

        return "\n".join(formatted_snippet)

    except Exception as e:
        logging.warning(f"Could not read code snippet from {full_file_path}: {e}")
        return None


def _construct_llm_prompt(vulnerability_details, code_snippet, is_dev_dep, prompt_type="analysis"):
    """
    Constructs the LLM prompt for either analysis or fix suggestion, demanding JSON output.
    """
    vuln_id = vulnerability_details.get('VulnerabilityID', 'N/A')
    severity = vulnerability_details.get('Severity', 'N/A')
    pkg_name = vulnerability_details.get('PkgName', 'N/A')
    installed_version = vulnerability_details.get('InstalledVersion', 'N/A')
    fixed_version = vulnerability_details.get('FixedVersion', 'N/A')
    file_path_for_prompt = vulnerability_details.get('FilePath', 'N/A')
    start_line_for_prompt = vulnerability_details.get('StartLine', 'N/A')
    end_line_for_prompt = vulnerability_details.get('EndLine', 'N/A')
    title = vulnerability_details.get('Title', 'N/A')
    description = vulnerability_details.get('Description', 'N/A')
    cwe_ids = ', '.join(vulnerability_details.get('CweIDs', []))
    primary_url = vulnerability_details.get('PrimaryURL', 'N/A')


    context_section = f"""
    Vulnerability Details:
    - ID: {vuln_id}
    - Severity: {severity}
    - Package Name: {pkg_name}
    - Installed Version: {installed_version}
    - Fixed Version (if available): {fixed_version}
    - Title: {title}
    - Description: {description}
    - CWE IDs: {cwe_ids}
    - More Info: {primary_url}
    - File Path: {file_path_for_prompt}
    - Start Line: {start_line_for_prompt}
    - End Line: {end_line_for_prompt}
    - Is Development Dependency: {'YES' if is_dev_dep else 'NO'}
    Relevant Code Snippet (if available, with vulnerable lines marked by '>>'):
    ```
    {code_snippet if code_snippet else 'No relevant code snippet could be extracted.'}
    ```
    """

    if prompt_type == "analysis":
        system_instruction = """
        You are a highly experienced security analyst specialized in code review and vulnerability assessment.
        Your task is to analyze the provided vulnerability details and determine if it's a **True Positive**, **False Positive**, or **Uncertain** for a typical production application.
        Pay close attention to the `File Path`, the `Code Snippet` (if provided), and the `Is Development Dependency` status to make your decision.

        **Guidance for Analysis:**
        - If `FilePath` points to a code file (e.g., `.js`, `.py`, `.java`) and a relevant `Code Snippet` is provided, use that snippet as primary context for "True Positive" or "False Positive" reasoning.
        - If `Is Development Dependency` is `YES`, it is highly likely a **False Positive** because development dependencies are typically not deployed to production environments.
        - If `FilePath` points to a dependency manifest (e.g., `package.json`, `package-lock.json`, `pom.xml`, `requirements.txt`) and NO specific code snippet related to its usage is provided:
            - **Consider it a True Positive** if the `Severity` is HIGH or CRITICAL, AND `Is Development Dependency` is `NO`. Assume it's a production dependency.
            - **Consider it a True Positive** if the `Severity` is MEDIUM or LOW, AND `Is Development Dependency` is `NO`, and it's a core dependency commonly used in production applications.
            - **Consider it Uncertain** if the severity is LOW or MEDIUM, and there's no clear indication of its production use or impact from the provided details, AND `Is Development Dependency` is `NO`.

        **Consider a False Positive if:**
        - **The `Is Development Dependency` status is `YES`.** This is the primary criterion for marking a package vulnerability as False Positive.
        - The vulnerable code path appears unreachable or is not actively used in the provided snippet (if snippet exists).
        - The issue is in a test file, example code, or documentation, not production code.
        - It's a low-impact misconfiguration that is intentional and secured in this specific context.
        - It's a generic secret (e.g., "admin/password") in a non-production context.

        **Consider a True Positive if:**
        - It's a direct dependency vulnerability in a production dependency (`Is Development Dependency` is `NO`) AND the severity warrants attention.
        - The vulnerable code path is clearly used or appears reachable (if snippet exists).
        - It's a critical misconfiguration impacting security.
        - It's a clear, impactful secret in production code.

        **Consider Uncertain if:**
        - There isn't enough information from the provided details or code snippet to make a definitive judgment, especially for low/medium severity package vulnerabilities where context is limited and `Is Development Dependency` is `NO`.

        Your response MUST be in JSON format, adhere strictly to the following structure.
        Do NOT include any other text or markdown outside the JSON block.

        ```json
        {
            "VulnerabilityID": "VULN_ID_HERE",
            "Analysis": "True Positive/False Positive/Uncertain",
            "Reasoning": "Brief explanation based on the details, code snippet, and dev dependency status."
        }
        ```
        Ensure "VULN_ID_HERE" is replaced with the actual ID.
        """
        prompt = system_instruction + context_section
        return prompt

    elif prompt_type == "fix_suggestion":
        system_instruction = """
        You are a highly experienced security expert providing concise and actionable remediation advice.
        Given the following vulnerability details and the relevant code snippet (if applicable), suggest the best way to fix it.

        **Instructions:**
        - If it's a package/dependency vulnerability, provide the exact upgrade command for `npm` or `yarn` (e.g., `npm update <pkg>@<version>`). Specify the target fixed version.
        - If it's a code-related vulnerability (e.g., misconfiguration, secret, SAST finding related to logic), provide specific code changes or detailed steps.
        - Be as specific as possible, referencing file paths and line numbers if relevant.
        - If multiple fixed versions are available, choose the latest stable one.
        - If the fix involves a code patch, provide `OldCode` and `NewCode` as exact replacements.
        - **CRITICAL**: When including code snippets in `OldCode` or `NewCode` fields, ensure that **all backslashes (`\`) are properly escaped as double backslashes (`\\`)**. For example, `\d` in regex should be represented as `\\d` in the JSON string. This is crucial for valid JSON parsing.
        - Be concise in your `FixSuggestion` and `ReasonForIgnore`.

        Your response MUST be in JSON format, adhere strictly to the following structure.
        Do NOT include any other text or markdown outside the JSON block.

        ```json
        {
            "VulnerabilityID": "VULN_ID_HERE",
            "FixSuggestion": "A concrete, actionable step to fix the vulnerability.",
            "ActionType": "one of: 'package_upgrade', 'code_patch', 'remove_dependency', 'ignore', 'manual_review'",
            "Details": {
                "FilePath": "path/to/file.ext_affected_if_code_patch",
                "LineStart": 0,
                "LineEnd": 0,
                "OldCode": "Original code snippet. Remember to escape backslashes, e.g., use \\\\d for \\d in regex.",
                "NewCode": "New code snippet. Remember to escape backslashes, e.g., use \\\\d for \\d in regex.",
                "PackageName": "package-name-if-upgrade",
                "TargetVersion": "target-version-if-upgrade",
                "ReasonForIgnore": "Brief reason if ActionType is 'ignore'"
            }
        }
        ```
        Ensure "VULN_ID_HERE" is replaced with the actual ID.
        Ensure that 'FilePath', 'LineStart', 'LineEnd', 'OldCode', 'NewCode' are ONLY present and populated if `ActionType` is 'code_patch'. For 'package_upgrade', populate 'PackageName' and 'TargetVersion'. For 'ignore', populate 'ReasonForIgnore'. Otherwise, set these specific fields to null or empty string. Make sure `LineStart` and `LineEnd` are integers.
        """
        prompt = system_instruction + context_section
        return prompt
    
    return "" # Should not reach here


def _parse_llm_response(llm_raw_output):
    """
    Attempts to extract and parse JSON from the LLM's raw output.
    """
    if not llm_raw_output:
        return None
    
    # Try to find a JSON block in the output
    try:
        # Look for the triple backticks and 'json'
        json_start_tag = "```json"
        json_end_tag = "```"
        
        start_idx = llm_raw_output.find(json_start_tag)
        if start_idx != -1:
            json_str = llm_raw_output[start_idx + len(json_start_tag):]
            end_idx = json_str.find(json_end_tag)
            if end_idx != -1:
                json_str = json_str[:end_idx].strip()
            
            return json.loads(json_str)
        
        # If no ```json block, try parsing the whole thing as JSON (less reliable but fallback)
        return json.loads(llm_raw_output.strip())

    except json.JSONDecodeError as e:
        logging.error(f"Failed to parse LLM JSON response: {e}")
        logging.error(f"Problematic LLM output (first 500 chars): {llm_raw_output[:500]}...")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred while parsing LLM response: {e}")
        return None


# Helper functions (defined within llm_processor.py to avoid import issues)
def analyze_with_llm(vulnerability_details):
    """
    Asks the LLM to analyze a vulnerability and determine true/false positive.
    Returns parsed JSON.
    """
    code_snippet = vulnerability_details.get("CodeSnippet")
    is_dev_dep = vulnerability_details.get("IsDevDependency", False) 
    prompt_content = _construct_llm_prompt(vulnerability_details, code_snippet, is_dev_dep, prompt_type="analysis")

    try:
        logging.info("Sending analysis prompt to LLM...")
        response = ollama.chat(
            model=OLLAMA_MODEL_NAME, 
            messages=[{'role': 'user', 'content': prompt_content}]
        )
        if response and response['message'] and response['message']['content']:
            llm_raw_output = response['message']['content']
            logging.debug(f"Raw LLM analysis output: {llm_raw_output}")
            parsed_response = _parse_llm_response(llm_raw_output)
            if parsed_response:
                return parsed_response
            else:
                logging.warning(f"Failed to parse analysis JSON for ID {vulnerability_details.get('VulnerabilityID')}.")
                return {"VulnerabilityID": vulnerability_details.get('VulnerabilityID'), "Analysis": "Parsing Failed", "Reasoning": "Could not parse LLM JSON response."}
        else:
            logging.warning(f"Ollama analysis response might be empty for ID {vulnerability_details.get('VulnerabilityID')}.")
            return {"VulnerabilityID": vulnerability_details.get('VulnerabilityID'), "Analysis": "No Content", "Reasoning": "Ollama returned empty response."}
    except Exception as e:
        logging.error(f"Error calling Ollama API for analysis {vulnerability_details.get('VulnerabilityID')}: {e}")
        return {"VulnerabilityID": vulnerability_details.get('VulnerabilityID'), "Analysis": "API Error", "Reasoning": f"Ollama API Error: {e}"}


def suggest_fix_with_llm(vulnerability_details):
    """
    Asks the LLM to suggest a fix for a given vulnerability.
    Returns parsed JSON.
    """
    code_snippet = vulnerability_details.get("CodeSnippet")
    is_dev_dep = vulnerability_details.get("IsDevDependency", False) 
    prompt_content = _construct_llm_prompt(vulnerability_details, code_snippet, is_dev_dep, prompt_type="fix_suggestion")

    try:
        logging.info("Sending fix suggestion prompt to LLM...")
        response = ollama.chat(
            model=OLLAMA_MODEL_NAME, 
            messages=[{'role': 'user', 'content': prompt_content}]
        )
        if response and response['message'] and response['message']['content']:
            llm_raw_output = response['message']['content']
            logging.debug(f"Raw LLM fix suggestion output: {llm_raw_output}")
            parsed_response = _parse_llm_response(llm_raw_output)
            if parsed_response:
                return parsed_response
            else:
                logging.warning(f"Failed to parse fix suggestion JSON for ID {vulnerability_details.get('VulnerabilityID')}.")
                return {"VulnerabilityID": vulnerability_details.get('VulnerabilityID'), "FixSuggestion": "Parsing Failed", "ActionType": "manual_review", "Details": {}}
        else:
            logging.warning(f"Ollama fix suggestion response might be empty for ID {vulnerability_details.get('VulnerabilityID')}.")
            return {"VulnerabilityID": vulnerability_details.get('VulnerabilityID'), "FixSuggestion": "No Content", "ActionType": "manual_review", "Details": {}}
    except Exception as e:
        logging.error(f"Error calling Ollama API for fix suggestion {vulnerability_details.get('VulnerabilityID')}: {e}")
        return {"VulnerabilityID": vulnerability_details.get('VulnerabilityID'), "FixSuggestion": f"API Error: {e}", "ActionType": "manual_review", "Details": {}}


def process_vulnerabilities_with_llm(vulnerabilities, repo_root_path, actionable_fixes_output_path=None):
    """
    Processes a list of vulnerabilities by calling the LLM for analysis and fix suggestions.
    Includes code snippets and dev dependency status if available.
    Sets the current working directory to the repo_root_path for proper file lookup.
    Returns a list of dictionaries, each containing original vuln details + LLM analysis/fix.
    Optionally saves actionable True Positives to a specified JSON file.
    """
    llm_processed_results = []
    actionable_fixes = []
    
    if not vulnerabilities:
        logging.info("No vulnerabilities found to process with LLM.")
        return []

    # Store current working directory to restore later
    original_cwd = os.getcwd()
    try:
        # Change current working directory to the repository root
        if repo_root_path and os.path.isdir(repo_root_path):
            os.chdir(repo_root_path)
            logging.debug(f"Changed CWD to {os.getcwd()} for file lookups.")
        else:
            logging.warning(f"Invalid repo_root_path provided: {repo_root_path}. Staying in original CWD, file lookups may fail.")

        logging.info(f"\n--- LLM Analysis of {len(vulnerabilities)} Vulnerabilities ---")
        for i, vuln in enumerate(vulnerabilities):
            vuln_id = vuln.get('VulnerabilityID', 'N/A')
            logging.info(f"\nProcessing Vulnerability {i+1}/{len(vulnerabilities)}: {vuln_id} - {vuln.get('Title', 'N/A')}")
            
            is_dev_dep = False
            if vuln.get("Type") == "npm" and vuln.get("PkgName"): 
                is_dev_dep = _is_dev_dependency(os.getcwd(), vuln["PkgName"])
            vuln["IsDevDependency"] = is_dev_dep

            code_snippet = None
            if vuln.get("FilePath"):
                code_snippet = read_code_snippet(vuln["FilePath"], vuln.get("StartLine"), vuln.get("EndLine"))
            vuln["CodeSnippet"] = code_snippet

            # Call LLM for analysis
            analysis_result = analyze_with_llm(vuln)
            
            # Call LLM for fix suggestion
            fix_suggestion_result = suggest_fix_with_llm(vuln)
            
            # Combine results
            combined_result = {
                "OriginalVulnerability": vuln, 
                "LLMAnalysis": analysis_result,
                "LLMFixSuggestion": fix_suggestion_result
            }
            llm_processed_results.append(combined_result)

            # actionable True Positives
            if (analysis_result.get('Analysis') == "True Positive" and
                fix_suggestion_result.get('ActionType') in ["package_upgrade", "code_patch"]):
                
                # We need to ensure FilePath is relative to repo_root for auto-patching
                fix_details = fix_suggestion_result.get('Details', {})

                relative_file_path = fix_details.get('FilePath')
                if relative_file_path and repo_root_path:
                    # Construct full path relative to where script was *run*
                    full_path_at_run = os.path.join(original_cwd, relative_file_path)
                    # Convert it to be relative to the *repo_root_path*
                    if os.path.exists(full_path_at_run): 
                         relative_file_path = os.path.relpath(full_path_at_run, repo_root_path)
                
                
                fix_details['FilePath'] = relative_file_path


                actionable_fixes.append({
                    "VulnerabilityID": vuln_id,
                    "Title": vuln.get('Title'),
                    "Description": vuln.get('Description'),
                    "Severity": vuln.get('Severity'),
                    "LLMAnalysis": analysis_result,
                    "LLMFixSuggestion": {
                        "FixSuggestion": fix_suggestion_result.get('FixSuggestion'),
                        "ActionType": fix_suggestion_result.get('ActionType'),
                        "Details": fix_details
                    }
                })
                logging.info(f"  --> Identified as an actionable True Positive for auto-remediation.")


            # OUTPUT 
            logging.info(f"  Vulnerability ID: {vuln_id}")
            logging.info(f"  Issue: {vuln.get('Title', 'N/A')}")
            logging.info(f"  Location: {vuln.get('FilePath', 'N/A')}" + (f":L{vuln['StartLine']}-L{vuln['EndLine']}" if vuln.get('StartLine') else ""))
            
            # Analysis Summary
            analysis_status = analysis_result.get('Analysis', 'N/A')
            analysis_reasoning = analysis_result.get('Reasoning', 'No reasoning provided.')
            logging.info(f"  Analysis: {analysis_status}")
            logging.info(f"    Reasoning: {analysis_reasoning}")

            # Fix Suggestion Summary
            fix_suggestion_text = fix_suggestion_result.get('FixSuggestion', 'No fix suggestion provided.')
            action_type = fix_suggestion_result.get('ActionType', 'manual_review')
            logging.info(f"  Fix Suggestion ({action_type}): {fix_suggestion_text}")

            if action_type == 'package_upgrade':
                pkg_name = fix_suggestion_result.get('Details', {}).get('PackageName', 'N/A')
                target_version = fix_suggestion_result.get('Details', {}).get('TargetVersion', 'N/A')
                logging.info(f"    Package: {pkg_name}, Target Version: {target_version}")
            elif action_type == 'code_patch':
                old_code_snippet = fix_suggestion_result.get('Details', {}).get('OldCode', 'N/A')
                new_code_snippet = fix_suggestion_result.get('Details', {}).get('NewCode', 'N/A')
                logging.info(f"    Old Code Snippet:\n```\n{old_code_snippet}\n```")
                logging.info(f"    New Code Snippet:\n```\n{new_code_snippet}\n```")
            elif action_type == 'ignore':
                reason_ignore = fix_suggestion_result.get('Details', {}).get('ReasonForIgnore', 'N/A')
                logging.info(f"    Reason to Ignore: {reason_ignore}")
            
            logging.info("-" * 50) 
            
        # Writing actionable fixes to file 
        
        base_dir = os.path.dirname(os.path.abspath(__file__)) 
        reports_dir = os.path.join(base_dir, "reports")
        actionable_fixes_output_path = os.path.join(reports_dir, "actionable_fixes.json")
        
        if actionable_fixes_output_path:
            try:
                output_dir_for_fixes = os.path.dirname(actionable_fixes_output_path)
                if output_dir_for_fixes:
                    os.makedirs(output_dir_for_fixes, exist_ok=True)
                    
                logging.info(f"📁 Current working directory: {os.getcwd()}")
                logging.info(f"📄 Saving actionable fixes to: {actionable_fixes_output_path}")
                
                with open(actionable_fixes_output_path, 'w', encoding='utf-8') as f:
                    json.dump(actionable_fixes, f, indent=4)
                
                logging.info(f"\nActionable True Positives saved to: {actionable_fixes_output_path}")

            
                if not os.path.exists(actionable_fixes_output_path):
                    logging.error(f"CRITICAL: File '{actionable_fixes_output_path}' was reported saved, but it does NOT exist on disk immediately after writing. This points to external interference (e.g., antivirus).")
                else:
                    logging.info("✅ Verified: File exists on disk after saving.")

            except Exception as e:
                logging.error(f"Failed to write actionable fixes to {actionable_fixes_output_path}: {e}")
                logging.error(traceback.format_exc())

    finally:
        # Restore original working directory
        if os.getcwd() != original_cwd:
            os.chdir(original_cwd)
            logging.debug(f"Restored CWD to {os.getcwd()}.")
            
    return llm_processed_results 