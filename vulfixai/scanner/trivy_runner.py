import subprocess
import os
import datetime
import tempfile 
import shutil  

def run_trivy_scan(target_path, report_path=None, scan_type="fs"):
    os.makedirs("reports", exist_ok=True)

    if not report_path:
        timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        report_path = f"reports/report-{timestamp}.json"

    # Initializing path for the actual content Trivy will scan
    trivy_scan_target = None
    # Initializing path to the root of the content being scanned (e.g., cloned repo root or local dir)
    repo_root_for_llm = None

    if scan_type == "repo":
        # Creates a temporary directory for cloning the repository
        temp_clone_dir = tempfile.mkdtemp()
        try:
            print(f"Cloning repository '{target_path}' into temporary directory: {temp_clone_dir}")
            # Use git.exe directly if it's not in PATH, otherwise 'git' is fine
            subprocess.run(['git', 'clone', target_path, temp_clone_dir], check=True, capture_output=True, text=True)
            trivy_scan_target = temp_clone_dir # Trivy scans the local cloned directory
            repo_root_for_llm = temp_clone_dir # This is the root for LLM to find package.json
            print("Repository cloned successfully.")
        except subprocess.CalledProcessError as e:
            print(f"❌ Git clone failed with error code {e.returncode}.")
            print(f"STDOUT: {e.stdout}")
            print(f"STDERR: {e.stderr}")
        
            if os.path.exists(temp_clone_dir):
                shutil.rmtree(temp_clone_dir)
            return None, None 
        
        except FileNotFoundError:
            print("❌ 'git' command not found. Please ensure Git is installed and in your system's PATH.")
            if os.path.exists(temp_clone_dir):
                shutil.rmtree(temp_clone_dir)
            return None, None
    else: # scan_type == "fs"
        trivy_scan_target = target_path
        repo_root_for_llm = target_path # For filesystem scan, the target is the root

    # Trivy command
    trivy_cmd = [
        r"D:\downloads13.08.2024\trivy_0.62.1_windows-64bit\trivy.exe",
        scan_type, # This will be "fs" or "repo"
        "--scanners", "vuln,secret,misconfig",
        "--format", "json",
        "--output", report_path,
        trivy_scan_target # This is the actual path Trivy will scan
    ]

    try:
        print(f"Running Trivy command: {' '.join(trivy_cmd)}")
        # Run the Trivy scan
        result = subprocess.run(trivy_cmd, check=True, capture_output=True, text=True)
        print("Trivy scan completed.")
        print(f"Trivy STDOUT:\n{result.stdout}")
        print(f"Trivy STDERR:\n{result.stderr}")
        
        # Return both the report path and the root path for LLM processing
        return report_path, repo_root_for_llm
    except subprocess.CalledProcessError as e:
        print(f"❌ Trivy failed with error code {e.returncode}.")
        print(f"Command: {' '.join(trivy_cmd)}")
        print(f"STDOUT: {e.stdout}")
        print(f"STDERR: {e.stderr}")
        return None, repo_root_for_llm # Still return repo_root_for_llm for potential cleanup
    except FileNotFoundError:
        print("❌ Trivy executable not found. Please check the path to trivy.exe.")
        return None, repo_root_for_llm