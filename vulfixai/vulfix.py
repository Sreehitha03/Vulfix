import argparse
import os
import json
import logging
import shutil 

logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')

from scanner.trivy_runner import run_trivy_scan
from analyzer.llm_processor import load_and_parse_trivy_report, process_vulnerabilities_with_llm

def main():
    parser = argparse.ArgumentParser(description="VulFix AI CLI")
    
    parser.add_argument("source", help="Path to local file/directory, URL of the Git repository, or path to an existing Trivy JSON report.")
    parser.add_argument("--type", choices=["repo", "dir", "report"], default="dir", # Expanded choices: 'fs' is now 'dir'
                        help="Type of scan: 'repo' (Git repository URL), 'dir' (local directory), or 'report' (existing Trivy JSON report). Defaults to 'dir'.")
    parser.add_argument("--output", help="Path to save the main LLM-processed JSON report", default="llm_processed_vulnerabilities.json") 
    parser.add_argument("--summary-output", default="pr_summary.md",
                        help="Path to save the concise Markdown summary for PR comments. Defaults to 'pr_summary.md'.")
    parser.add_argument("--actionable-fixes-output", default="actionable_fixes.json",
                        help="Path to save a JSON report of only actionable True Positives. Defaults to 'actionable_fixes.json'.")
    parser.add_argument("--skip-scan", action="store_true",
                        help="If set, skip the Trivy scan phase and only process an existing Trivy report. 'source' must be a report path.")
    parser.add_argument("--no-llm", action="store_true", help="Skip LLM processing for scan results.")


    args = parser.parse_args()

    report_path = None
    repo_root_for_llm = None 

    try:
        if args.skip_scan:
            if args.type != 'report':
                logging.error("--skip-scan can only be used with --type report.")
                return
            report_path = args.source # User provides the existing report directly
            if not os.path.exists(report_path):
                logging.error(f"Provided Trivy report '{report_path}' not found.")
                return
            # For 'report' type with skip-scan, derive repo_root_for_llm from report's directory
            # If the report is in the current directory, os.path.dirname might return empty string
            repo_root_for_llm = os.path.dirname(report_path)
            if not repo_root_for_llm: # If report is in current dir
                repo_root_for_llm = os.getcwd()
            
            logging.info(f"⏭️ Skipping Trivy scan and processing existing report: {report_path}")
        else: # Perform a new scan (repo or dir)
            logging.info(f"🔍 Running Trivy Scan for {args.type.upper()} target: {args.source}...")
            # CALLING YOUR EXISTING run_trivy_scan from scanner.trivy_runner
            # This function return (report_path, repo_root_path)
            report_path, repo_root_for_llm = run_trivy_scan(args.source, "trivy_report_temp.json", args.type) 

            if not report_path:
                logging.error("❌ Trivy scan failed. Exiting.")
                return 

            logging.info(f"✅ Scan complete. Raw Trivy report saved to {report_path}")

        #  LLM Processing Phase
        if not args.no_llm:
            logging.info("🧠 Analyzing scan results with LLM...")
            vulnerabilities = load_and_parse_trivy_report(report_path)
            if vulnerabilities:
                if repo_root_for_llm:
                    # Pass the actionable_fixes_output_path
                    llm_processed_results = process_vulnerabilities_with_llm(
                        vulnerabilities, 
                        repo_root_for_llm, 
                        actionable_fixes_output_path=args.actionable_fixes_output
                    )
                else:
                    logging.warning("Warning: Could not determine repository root for LLM processing. Using current directory as fallback.")
                    llm_processed_results = process_vulnerabilities_with_llm(
                        vulnerabilities, 
                        os.getcwd(), 
                        actionable_fixes_output_path=args.actionable_fixes_output
                    )
                
                # Save the full LLM processed report
                try:
                    os.makedirs(os.path.dirname(args.output), exist_ok=True)
                    with open(args.output, 'w', encoding='utf-8') as f:
                        json.dump(llm_processed_results, f, indent=4)
                    logging.info(f"Full LLM processed report saved to {args.output}")
                except Exception as e:
                    logging.error(f"Failed to write full LLM processed report: {e}")

                # Generate and save summary for PR comment
                try:
                    summary_content = []
                    # Use args.source for display if repo_root_for_llm is still None (e.g., if report type and source is just a file name)
                    display_source = repo_root_for_llm if repo_root_for_llm and os.path.exists(repo_root_for_llm) else args.source
                    summary_content.append(f"## Vulnerability Scan Results for {display_source}\n")
                    summary_content.append(f"Scan completed on: {os.path.basename(os.path.normpath(display_source))}\n")
                    summary_content.append(f"Total vulnerabilities detected by Trivy: {len(vulnerabilities)}\n")
                    summary_content.append(f"Total vulnerabilities processed by LLM: {len(llm_processed_results)}\n")
                    summary_content.append("\n### LLM Analysis Summary:\n")

                    true_positives_count = 0
                    false_positives_count = 0
                    uncertain_count = 0
                    actionable_count = 0

                    for result in llm_processed_results:
                        analysis_status = result['LLMAnalysis'].get('Analysis', 'N/A')
                        vuln_id = result['OriginalVulnerability'].get('VulnerabilityID', 'N/A')
                        title = result['OriginalVulnerability'].get('Title', 'N/A')
                        location = result['OriginalVulnerability'].get('FilePath', 'N/A')
                        action_type = result['LLMFixSuggestion'].get('ActionType', 'manual_review')

                        summary_content.append(f"- **{vuln_id}**: {title}")
                        summary_content.append(f"  - **Analysis**: `{analysis_status}`")
                        summary_content.append(f"  - **Reasoning**: {result['LLMAnalysis'].get('Reasoning', 'N/A')}")
                        summary_content.append(f"  - **Fix Suggestion**: {result['LLMFixSuggestion'].get('FixSuggestion', 'N/A')} (`{action_type}`)")
                        summary_content.append(f"  - **Location**: `{location}`")
                        summary_content.append("\n")

                        if analysis_status == "True Positive":
                            true_positives_count += 1
                            if action_type in ["package_upgrade", "code_patch"]:
                                actionable_count += 1
                        elif analysis_status == "False Positive":
                            false_positives_count += 1
                        elif analysis_status == "Uncertain":
                            uncertain_count += 1

                    summary_content.insert(4, f"True Positives: {true_positives_count}\n")
                    summary_content.insert(5, f"False Positives: {false_positives_count}\n")
                    summary_content.insert(6, f"Uncertain: {uncertain_count}\n")
                    summary_content.insert(7, f"**Actionable True Positives for auto-remediation: {actionable_count}**\n")


                    summary_output_dir = os.path.dirname(args.summary_output)
                    if summary_output_dir: 
                        os.makedirs(summary_output_dir, exist_ok=True)
                    with open(args.summary_output, 'w', encoding='utf-8') as f:
                        f.write("".join(summary_content))
                    logging.info(f"Markdown summary for PR saved to {args.summary_output}")
                except Exception as e:
                    logging.error(f"Failed to generate Markdown summary: {e}")

            else:
                logging.info("No vulnerabilities found or report parsing failed. Skipping LLM processing.")
        else:
            logging.info("⏭️ LLM processing skipped as requested.")

    finally:
        # Clean up the temporary Trivy report if it was generated by us 
        if report_path and os.path.exists(report_path) and args.type != 'report':
            logging.info(f"🗑️ Cleaning up temporary Trivy report: {report_path}")
            try:
                os.remove(report_path)
            except Exception as e:
                logging.error(f"Error cleaning up temporary report {report_path}: {e}")

        # Clean up the cloned repository if it was a 'repo' scan
        # This relies on repo_root_for_llm being the temporary clone path
        if args.type == "repo" and repo_root_for_llm and os.path.exists(repo_root_for_llm):
            logging.info(f"🗑️ Cleaning up temporary cloned repository: {repo_root_for_llm}")
            try:
                shutil.rmtree(repo_root_for_llm)
                logging.info("Temporary repository cleaned up successfully.")
            except Exception as e:
                logging.error(f"Error cleaning up temporary repository {repo_root_for_llm}: {e}")


if __name__ == "__main__":
    main()