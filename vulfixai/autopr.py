import os
import json
import logging
import subprocess
import shutil
import traceback
from github import Github
from git import Repo, GitCommandError
from dotenv import load_dotenv 

load_dotenv() 

logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')

def create_pull_requests(repo_url, actionable_fixes_path, github_token):
    """
    Reads actionable fixes from a JSON file, applies them to a cloned repository,
    and creates GitHub Pull Requests for each fix.
    """
    if not github_token:
        logging.error("GitHub Personal Access Token (GITHUB_TOKEN) not found in environment variables.")
        logging.error("Please set the GITHUB_TOKEN environment variable in your .env file or system environment.")
        return

    # Load Actionable Fixes
    actionable_fixes = []
    try:
        with open(actionable_fixes_path, 'r', encoding='utf-8') as f:
            actionable_fixes = json.load(f)
        
        if not actionable_fixes:
            logging.info("No actionable fixes found in the provided JSON file. No PRs to create.")
            return
        
        logging.info(f"Loaded {len(actionable_fixes)} actionable fixes from '{actionable_fixes_path}'.")
    except FileNotFoundError:
        logging.error(f"Actionable fixes file not found at '{actionable_fixes_path}'. Please ensure the path is correct.")
        return
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON from '{actionable_fixes_path}'. Is it a valid JSON file? Error: {e}")
        return
    except Exception as e:
        logging.error(f"An unexpected error occurred while loading actionable fixes: {e}")
        logging.error(traceback.format_exc())
        return

    parts = repo_url.rstrip('/').split('/')
    if len(parts) < 2:
        logging.error(f"Invalid GitHub repository URL format: '{repo_url}'. Expected format like 'https://github.com/owner/repo.git'.")
        return
    
    repo_name_with_git = parts[-1]
    repo_name = repo_name_with_git.replace('.git', '')
    repo_owner = parts[-2]

    logging.info(f"Targeting GitHub repository: '{repo_owner}/{repo_name}'.")

    # Initialize GitHub API client
    g = Github(github_token)
    try:
        github_repo = g.get_user(repo_owner).get_repo(repo_name)
        logging.info(f"Successfully connected to GitHub repository '{repo_owner}/{repo_name}'.")
    except Exception as e:
        logging.error(f"Failed to access GitHub repository '{repo_owner}/{repo_name}'. Please check your GITHUB_TOKEN permissions or if the repository exists. Error: {e}")
        logging.error(traceback.format_exc())
        return

    # Defining a temporary directory for cloning the repository
    temp_clone_dir = os.path.join(os.getcwd(), f"vulfixai_temp_clone_{os.urandom(8).hex()}")

    local_repo = None 
    try:
        
        logging.info(f"Cloning '{repo_url}' into '{temp_clone_dir}'...")
        # For HTTPS cloning with PAT, embed the token in the URL for GitPython
        repo_auth_url = f"https://{github_token}@github.com/{repo_owner}/{repo_name}.git"
        local_repo = Repo.clone_from(repo_auth_url, temp_clone_dir)
        logging.info("Repository cloned successfully.")

        base_branch = github_repo.default_branch # default branch (e.g., 'main' or 'master')
        logging.info(f"Default branch of the repository is: '{base_branch}'.")
        local_repo.git.checkout(base_branch) # Ensure we're on the default branch

        processed_vulnerabilities = set() # To track unique fixes already attempted/processed

        # Process each actionable fix
        for i, fix in enumerate(actionable_fixes):
            vulnerability_id = fix.get("VulnerabilityID", f"unknown_vuln_{i+1}")
            
            # Extract LLM fix suggestion details safely
            llm_fix_suggestion = fix.get("LLMFixSuggestion", {})
            fix_suggestion_text = llm_fix_suggestion.get("FixSuggestion", "No specific fix suggestion provided by LLM.")
            action_type = llm_fix_suggestion.get("ActionType", "unknown")
            fix_details = llm_fix_suggestion.get("Details", {})

            # Determine a unique key for this fix (e.g., VulnID + PackageName + TargetVersion)
       
            fix_key = (vulnerability_id, 
                       fix_details.get("PackageName"), 
                       fix_details.get("TargetVersion"))

            if fix_key in processed_vulnerabilities:
                logging.info(f"Fix for '{vulnerability_id}' (Package: {fix_key[1]}, Version: {fix_key[2]}) has already been processed or is a duplicate. Skipping.")
                continue
            
            processed_vulnerabilities.add(fix_key) 

            logging.info(f"\n--- Processing fix for Vulnerability ID: '{vulnerability_id}' (Action Type: '{action_type}') ---")

            # Sanitize branch name: replace special characters with hyphens
            branch_name_safe = f"vulfixai-fix-{vulnerability_id.lower().replace('.', '-')}-{action_type}"
            branch_name_safe = ''.join(c if c.isalnum() or c == '-' else '_' for c in branch_name_safe)
            branch_name_safe = branch_name_safe.replace('__', '_').strip('_') 

            logging.info(f"Proposed branch name: '{branch_name_safe}'.")

            # Create and checkout a new branch for the fix
            try:
                local_repo.git.checkout(base_branch) 
                local_repo.git.checkout('-b', branch_name_safe)
                logging.info(f"Created and checked out new branch: '{branch_name_safe}'.")
            except GitCommandError as e:
                logging.error(f"Failed to create/checkout branch '{branch_name_safe}' for '{vulnerability_id}': {e}")
                logging.info("Skipping this fix and moving to the next.")
                continue # Move to the next fix if branch creation fails

            # Apply the fix based on ActionType 
            changes_made = False # Flag to track if actual changes were applied
            if action_type == "package_upgrade":
                package_name = fix_details.get("PackageName")
                target_version = fix_details.get("TargetVersion")
            
                relative_project_path = os.path.dirname(fix_details.get("FilePath", ""))

                if not (package_name and target_version and relative_project_path):
                    logging.warning(f"Missing essential details (PackageName, TargetVersion, FilePath) for package_upgrade fix for '{vulnerability_id}'. Skipping.")
                    continue
                
                # Correctly join the temporary clone directory with the relative project path
                # This will form 'vulfixai_temp_clone_XXXX/Travel Tracker'
                project_dir = os.path.join(temp_clone_dir, relative_project_path)
                
                # Now, the package.json will be correctly found inside this 'project_dir'
                package_json_path = os.path.join(project_dir, "package.json")
                
                if not os.path.exists(package_json_path):
                    logging.error(f"package.json not found at expected path '{package_json_path}'. "
                                  f"This suggests the path derived from actionable_fixes.json ('{relative_project_path}') "
                                  f"or the actual repository structure might be different than expected. Skipping fix for '{vulnerability_id}'.")
                    continue

                logging.info(f"Attempting to upgrade '{package_name}' to '{target_version}' in '{package_json_path}'.")

                try:

                    with open(package_json_path, 'r', encoding='utf-8') as f:
                        package_json_data = json.load(f)

                    # 2. Modify package version in 'dependencies' or 'devDependencies'
                    package_found_and_updated = False
                    if 'dependencies' in package_json_data and package_name in package_json_data['dependencies']:
                        package_json_data['dependencies'][package_name] = f"^{target_version}" # Use caret for compatible version
                        package_found_and_updated = True
                    elif 'devDependencies' in package_json_data and package_name in package_json_data['devDependencies']:
                        package_json_data['devDependencies'][package_name] = f"^{target_version}"
                        package_found_and_updated = True
                    
                    if not package_found_and_updated:
                        logging.warning(f"Package '{package_name}' not found in 'dependencies' or 'devDependencies' of '{package_json_path}'. Skipping upgrade for '{vulnerability_id}'.")
                        continue

                    # 3. Write modified package.json back
                    with open(package_json_path, 'w', encoding='utf-8') as f:
                        json.dump(package_json_data, f, indent=2)
                    logging.info(f"Updated '{package_name}' version in '{package_json_path}'.")
                    changes_made = True # Flag that package.json was modified

                    # 4. Run 'npm install' in the project directory to update package-lock.json
                    logging.info(f"Running 'npm install' in '{project_dir}' to update package-lock.json...")
                    
                    npm_command = [r"C:\Program Files\nodejs\npm.cmd", "install"]
                    
                    process = subprocess.run(npm_command, cwd=project_dir, capture_output=True, text=True, check=False)

                    if process.returncode == 0:
                        logging.info("npm install completed successfully.")
                        # Check actually changes
                        if not local_repo.is_dirty(untracked_files=False):
                            logging.info("npm install ran, but no changes detected (e.g., package-lock.json was already up-to-date or package wasn't affected).")
                            changes_made = False 
                        
                    else:
                        logging.error(f"npm install failed for '{vulnerability_id}' in '{project_dir}'.")
                        logging.error(f"NPM Stdout:\n{process.stdout}")
                        logging.error(f"NPM Stderr:\n{process.stderr}")
                        logging.info("Skipping this fix due to npm install failure.")
                        changes_made = False 
                        continue 
                        
                except json.JSONDecodeError:
                    logging.error(f"Error parsing '{package_json_path}'. It might not be valid JSON. Skipping fix for '{vulnerability_id}'.")
                    continue
                except FileNotFoundError as e: # This FileNotFoundError means 'npm' executable itself wasn't found
                    logging.error(f"File not found during package upgrade for '{vulnerability_id}': {e}. Skipping fix.")
                    logging.error(f"This often means 'npm' is not in your system's PATH. Error Traceback:\n{traceback.format_exc()}")
                    continue
                except Exception as e:
                    logging.error(f"An unexpected error occurred during package upgrade for '{vulnerability_id}': {e}")
                    logging.error(traceback.format_exc())
                    continue
            elif action_type == "code_patch":
            
                logging.warning(f"Action type 'code_patch' for '{vulnerability_id}' is not automatically supported in this version. Manual review and application required.")
                continue
            else:
                logging.warning(f"Unsupported action type '{action_type}' for '{vulnerability_id}'. Skipping this fix.")
                continue

            # Add changes, commit, and push only if changes were successfully made and detected by Git
            if changes_made and local_repo.is_dirty(untracked_files=False):
                try:
                    local_repo.git.add(A=True) 
                    commit_message = f"VulfixAI: Fix {vulnerability_id} - {package_name} upgrade to {target_version}"
                    local_repo.index.commit(commit_message)
                    logging.info(f"Committed changes to branch '{branch_name_safe}'.")

                    remote = local_repo.remote('origin')
                    remote.push(branch_name_safe)
                    logging.info(f"Pushed branch '{branch_name_safe}' to remote GitHub repository.")
                except GitCommandError as e:
                    logging.error(f"Failed to commit or push changes for '{vulnerability_id}': {e}")
                    logging.info("Skipping PR creation for this fix due to Git error.")
                    continue
                except Exception as e:
                    logging.error(f"An unexpected error occurred during Git commit/push for '{vulnerability_id}': {e}")
                    logging.error(traceback.format_exc())
                    continue
            else:
                logging.info(f"No valid changes were applied or detected for '{vulnerability_id}'. Skipping commit/PR for this fix.")
                continue

            # Create Pull Request
            try:
                pr_title = f"VulfixAI: Fix {vulnerability_id} - {package_name} upgrade"
                pr_body = (
                    f"This Pull Request was automatically generated by VulfixAI to address:\n\n"
                    f"**Vulnerability ID:** {vulnerability_id}\n"
                    f"**Severity:** {fix.get('Severity', 'N/A')}\n" # Get Severity from top level of fix dict
                    f"**Title:** {fix.get('Title', 'N/A')}\n\n"
                    f"**LLM Fix Suggestion:**\n```\n{fix_suggestion_text}\n```\n\n"
                    f"**Action Type:** {action_type}\n"
                    f"**Details:**\n```json\n{json.dumps(fix_details, indent=2)}\n```\n\n"
                    f"Please review and merge if appropriate."
                )
                
                pull_request = github_repo.create_pull(
                    title=pr_title,
                    body=pr_body,
                    head=branch_name_safe,
                    base=base_branch # Target the default branch
                )
                logging.info(f"Pull Request created successfully: {pull_request.html_url}")
            except Exception as e:
                logging.error(f"Failed to create Pull Request for '{vulnerability_id}': {e}")
                logging.error(traceback.format_exc())

    except GitCommandError as e:
        logging.error(f"A critical Git operation failed during the process: {e}")
        logging.error(traceback.format_exc())
    except Exception as e:
        logging.error(f"An unexpected error occurred during the PR creation process: {e}")
        logging.error(traceback.format_exc())
    finally:

        if os.path.exists(temp_clone_dir):
            logging.info(f"Attempting to clean up temporary cloned repository: '{temp_clone_dir}'")
            try:
                shutil.rmtree(temp_clone_dir, ignore_errors=True) 

                logging.info("Temporary repository cleaned up successfully (or errors ignored).")
            except Exception as e:
                logging.error(f"Error cleaning up temporary repository '{temp_clone_dir}': {e}")
                logging.error(traceback.format_exc())


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Automate Pull Request creation for vulnerability fixes.")
    parser.add_argument("--repo-url", required=True, help="URL of the GitHub repository (e.g., https://github.com/owner/repo.git)")
    parser.add_argument("--actionable-fixes", default="reports/actionable_fixes.json",
                        help="Path to the JSON file containing actionable fixes (default: reports/actionable_fixes.json)")
    
    args = parser.parse_args()

    github_token = os.environ.get("GITHUB_TOKEN") 
    
    create_pull_requests(args.repo_url, args.actionable_fixes, github_token)