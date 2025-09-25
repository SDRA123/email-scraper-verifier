import os
import io
import sys
import time
import uuid
import shutil
import subprocess
from pathlib import Path
from datetime import datetime

import streamlit as st
import pandas as pd


PROJECT_DIR = Path(__file__).resolve().parent
WORK_DIR = PROJECT_DIR / "runs"
WORK_DIR.mkdir(exist_ok=True)


def write_temp_input(uploaded_file) -> Path:
    uid = uuid.uuid4().hex[:8]
    run_dir = WORK_DIR / f"run_{uid}"
    run_dir.mkdir(parents=True, exist_ok=True)
    input_path = run_dir / uploaded_file.name
    with open(input_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    return input_path


def stream_process(cmd, cwd: Path, log_callback):
    """
    Stream process output in real-time with immediate flushing
    """
    # Set environment to force unbuffered output
    env = os.environ.copy()
    env['PYTHONUNBUFFERED'] = '1'
    
    proc = subprocess.Popen(
        cmd,
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=0,  # Unbuffered
        universal_newlines=True,
        env=env
    )
    
    # Read output line by line with immediate flushing
    while True:
        line = proc.stdout.readline()
        if not line:
            break
        log_callback(line.rstrip())
        time.sleep(0.01)  # Small delay to ensure UI updates
    
    proc.wait()
    log_callback(f"[exit] code={proc.returncode}")
    return proc.returncode


def derive_intermediate_paths(input_path: Path, run_keyword: bool, run_blog: bool, run_email: bool):
    base_no_ext = input_path.with_suffix("")
    
    if run_keyword:
        base_keyword_no_ext = Path(str(base_no_ext) + "_filtered")
        keyword_out = base_keyword_no_ext.with_suffix(".xlsx")
    else:
        keyword_out = input_path
    
    if run_blog:
        blog_out = keyword_out  # blog script updates in-place
    else:
        blog_out = keyword_out
    
    if run_email:
        if run_keyword:
            final_out = Path(str(base_keyword_no_ext) + "_with_emails.xlsx")
        else:
            final_out = Path(str(base_no_ext) + "_with_emails.xlsx")
    else:
        final_out = blog_out
    
    return keyword_out, blog_out, final_out


def get_runs_history():
    """Get list of previous runs with metadata"""
    runs = []
    if WORK_DIR.exists():
        for run_dir in sorted(WORK_DIR.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
            if run_dir.is_dir() and run_dir.name.startswith("run_"):
                run_info = {
                    'id': run_dir.name,
                    'path': run_dir,
                    'created': datetime.fromtimestamp(run_dir.stat().st_mtime),
                    'files': []
                }
                
                # Get all files in the run directory
                for file_path in run_dir.iterdir():
                    if file_path.is_file():
                        run_info['files'].append({
                            'name': file_path.name,
                            'path': file_path,
                            'size': file_path.stat().st_size,
                            'modified': datetime.fromtimestamp(file_path.stat().st_mtime)
                        })
                
                runs.append(run_info)
    return runs


st.set_page_config(page_title="Guestpost Automation Runner", page_icon="🧭", layout="centered")
st.title("Guestpost Automation Runner")
st.caption("Upload an Excel with columns `URL` and `Organic Traffic`. Select which scripts to run.")

# Create tabs for main interface, email verification, and runs history
tab1, tab2, tab3 = st.tabs(["🚀 Run Pipeline", "📧 Email Verification", "📁 Runs History"])

with tab1:
    uploaded = st.file_uploader("Upload Excel (.xlsx or .csv)", type=["xlsx", "csv"])

    # Script selection
    st.subheader("Script Selection")
    col1, col2, col3 = st.columns(3)
    with col1:
        run_keyword = st.checkbox("1. Keyword Filter", value=True, help="Filter websites based on custom keywords")
    with col2:
        run_blog = st.checkbox("2. Blog Checker", value=True, help="Check for recent blog articles")
    with col3:
        run_email = st.checkbox("3. Email Scraper", value=True, help="Scrape contact emails")

    # Show pipeline order
    if run_keyword or run_blog or run_email:
        pipeline_steps = []
        if run_keyword:
            pipeline_steps.append("Keyword Filter")
        if run_blog:
            pipeline_steps.append("Blog Checker")
        if run_email:
            pipeline_steps.append("Email Scraper")
        
        st.info(f"Pipeline order: {' → '.join(pipeline_steps)}")

    # Configuration options
    st.subheader("Configuration")

    col_a, col_b = st.columns(2)
    with col_a:
        min_traffic = st.text_input("Min Organic Traffic (optional)", value="")
        keyword_include = st.text_input("Include keywords (comma-separated)", value="", help="Required: Keywords to search for in URLs")
        keyword_exclude = st.text_input("Exclude keywords (comma-separated)", value="", help="Optional: Keywords to exclude from results")
    with col_b:
        smtp_verify = st.checkbox("Enable SMTP verification (slower)", value=True)
        keyword_debug = st.checkbox("Keyword filter debug logs", value=False)
        keyword_csv = st.checkbox("Also save CSV from keyword filter", value=False)

    col_c, col_d = st.columns(2)
    with col_c:
        email_debug = st.checkbox("Email scraper debug logs", value=False)
    with col_d:
        email_fast_only = st.checkbox("Email scraper fast-only (no Selenium)", value=False)

    # Validation
    if not (run_keyword or run_blog or run_email):
        st.warning("Please select at least one script to run.")
        run_clicked = False
    elif run_keyword and not keyword_include.strip():
        st.warning("Please provide include keywords when using the keyword filter.")
        run_clicked = False
    else:
        run_clicked = st.button("Run Pipeline", type="primary", disabled=uploaded is None)

    # Create a container for the terminal log with fixed height and scroll
    st.subheader("Terminal Output")
    
    # Add CSS for scrollable log container
    st.markdown("""
    <style>
    .log-container {
        height: 400px;
        overflow-y: auto;
        border: 1px solid rgba(0,0,0,0.15);
        padding: 10px;
        background-color: #f8f9fa;
        border-radius: 5px;
        color: #111;
    }
    .log-container pre {
        margin: 0;
        white-space: pre-wrap;
        font-family: 'Courier New', monospace;
        font-size: 12px;
        color: inherit;
    }
    @media (prefers-color-scheme: dark) {
      .log-container {
        background-color: #0e1117; /* Streamlit dark bg */
        border-color: rgba(255,255,255,0.16);
        color: #e1e6f0; /* light text */
      }
    }
    </style>
    """, unsafe_allow_html=True)
    
    log_container = st.container()
    with log_container:
        log_box = st.empty()
    
    final_download = st.empty()

    if run_clicked and uploaded is not None:
        input_path = write_temp_input(uploaded)
        keyword_out, blog_out, final_out = derive_intermediate_paths(input_path, run_keyword, run_blog, run_email)

        logs = io.StringIO()
        def log(line: str):
            logs.write(line + "\n")
            # Use a scrollable container for the log
            log_content = logs.getvalue()
            log_box.markdown(f"""
            <div class="log-container">
                <pre style="margin: 0; white-space: pre-wrap; font-family: 'Courier New', monospace; font-size: 12px;">{log_content}</pre>
            </div>
            """, unsafe_allow_html=True)

        # Pre-run validation: required columns
        try:
            if input_path.suffix.lower() == ".xlsx":
                df_check = pd.read_excel(input_path)
            elif input_path.suffix.lower() == ".csv":
                df_check = pd.read_csv(input_path)
            else:
                st.error("Input must be .xlsx or .csv")
                st.stop()
        except Exception as e:
            st.error(f"Failed to read uploaded file: {e}")
            st.stop()

        required_cols = {"URL", "Organic Traffic"}
        if not required_cols.issubset(set(map(str, df_check.columns))):
            st.error("Uploaded file must contain columns: URL, Organic Traffic")
            st.stop()

        # 1) checkforkeywordsites.py
        if run_keyword:
            cmd1 = [sys.executable, str(PROJECT_DIR / "checkforkeywordsites.py"), str(input_path)]
            if min_traffic.strip():
                try:
                    float(min_traffic.strip())
                    cmd1 += ["--min-traffic", min_traffic.strip()]
                except ValueError:
                    log(f"[warn] Ignoring invalid min traffic: {min_traffic}")
            if keyword_include.strip():
                cmd1 += ["--include", keyword_include.strip()]
            if keyword_exclude.strip():
                cmd1 += ["--exclude", keyword_exclude.strip()]
            if keyword_debug:
                cmd1.append("--debug")
            if keyword_csv:
                cmd1.append("--csv")
            log("$ " + " ".join(cmd1))
            stream_process(cmd1, PROJECT_DIR, log)

            if not keyword_out.exists():
                log("[error] Keyword-filtered output not found. Aborting.")
                st.stop()

        # 2) checkforblogpage.py (updates file in-place)
        if run_blog:
            cmd2 = [sys.executable, str(PROJECT_DIR / "checkforblogpage.py"), str(keyword_out)]
            log("$ " + " ".join(cmd2))
            stream_process(cmd2, PROJECT_DIR, log)

            if not blog_out.exists():
                log("[error] Blog checker did not update the file. Aborting.")
                st.stop()

        # 3) emailscraper.py
        if run_email:
            cmd3 = [sys.executable, str(PROJECT_DIR / "emailscraper.py"), str(blog_out)]
            if not smtp_verify:
                cmd3.append("--no-smtp")
            if email_debug:
                cmd3.append("--debug")
            if email_fast_only:
                cmd3.append("--fast-only")
            log("$ " + " ".join(cmd3))
            stream_process(cmd3, PROJECT_DIR, log)

        # Download final result
        if final_out.exists():
            with open(final_out, "rb") as f:
                final_download.download_button(
                    label="Download Final Excel",
                    data=f.read(),
                    file_name=final_out.name,
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                )
            st.success("Pipeline complete.")
        else:
            st.warning("Pipeline finished but final file not found. Check logs above.")

# Email Verification Tab
with tab2:
    st.subheader("Email Verification")
    st.caption("Upload an Excel file with 'Email' or 'email' column, or paste emails directly below")
    
    # Input method selection
    input_method = st.radio("Choose input method:", ["Upload Excel File", "Paste Emails Directly"], horizontal=True)
    
    if input_method == "Upload Excel File":
        uploaded_verify = st.file_uploader("Upload Excel for Email Verification (.xlsx or .csv)", type=["xlsx", "csv"], key="verify_uploader")
        input_data = uploaded_verify
    else:
        st.subheader("Paste Emails")
        st.caption("Enter emails below. Each line can contain multiple emails separated by commas.")
        st.caption("Example:")
        st.code("john@example.com, jane@example.com\ncontact@company.com\ninfo@website.org, support@website.org")
        
        pasted_emails = st.text_area(
            "Paste your emails here:",
            height=200,
            placeholder="Enter emails here, one or more per line, separated by commas...",
            key="pasted_emails"
        )
        input_data = pasted_emails.strip() if pasted_emails else None
    
    if input_data is not None:
        # Configuration options for email verification
        st.subheader("Verification Settings")
        col_a, col_b = st.columns(2)
        with col_a:
            smtp_verify_emails = st.checkbox("Enable SMTP verification (slower but more accurate)", value=True, help="Disable for faster verification without SMTP checks")
        with col_b:
            verify_debug = st.checkbox("Show debug logs", value=False, help="Display detailed verification logs")
        
        verify_clicked = st.button("Verify Emails", type="primary")
        
        # Create a container for the terminal log with fixed height and scroll
        st.subheader("Verification Output")
        
        # Add CSS for scrollable log container
        st.markdown("""
        <style>
        .log-container {
            height: 400px;
            overflow-y: auto;
            border: 1px solid rgba(0,0,0,0.15);
            padding: 10px;
            background-color: #f8f9fa;
            border-radius: 5px;
            color: #111;
        }
        .log-container pre {
            margin: 0;
            white-space: pre-wrap;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            color: inherit;
        }
        @media (prefers-color-scheme: dark) {
          .log-container {
            background-color: #0e1117;
            border-color: rgba(255,255,255,0.16);
            color: #e1e6f0;
          }
        }
        </style>
        """, unsafe_allow_html=True)
        
        verify_log_container = st.container()
        with verify_log_container:
            verify_log_box = st.empty()
        
        verify_download = st.empty()
        
        if verify_clicked:
            logs_verify = io.StringIO()
            def log_verify(line: str):
                logs_verify.write(line + "\n")
                # Use a scrollable container for the log
                log_content = logs_verify.getvalue()
                verify_log_box.markdown(f"""
                <div class="log-container">
                    <pre style="margin: 0; white-space: pre-wrap; font-family: 'Courier New', monospace; font-size: 12px;">{log_content}</pre>
                </div>
                """, unsafe_allow_html=True)
            
            if input_method == "Upload Excel File":
                # Handle file upload
                input_path_verify = write_temp_input(uploaded_verify)
                
                # Pre-run validation: check for email column
                try:
                    if input_path_verify.suffix.lower() == ".xlsx":
                        df_check_verify = pd.read_excel(input_path_verify)
                    elif input_path_verify.suffix.lower() == ".csv":
                        df_check_verify = pd.read_csv(input_path_verify)
                    else:
                        st.error("Input must be .xlsx or .csv")
                        st.stop()
                except Exception as e:
                    st.error(f"Failed to read uploaded file: {e}")
                    st.stop()
                
                # Check for email column (case insensitive)
                email_col_found = None
                for col in df_check_verify.columns:
                    if col.lower() in ['email', 'emails']:
                        email_col_found = col
                        break
                
                if not email_col_found:
                    st.error("Uploaded file must contain a column named 'Email' or 'email'")
                    st.stop()
                
                log_verify(f"Found email column: '{email_col_found}'")
                log_verify(f"SMTP verification: {'Enabled' if smtp_verify_emails else 'Disabled'}")
                
                # Run email verification
                cmd_verify = [sys.executable, str(PROJECT_DIR / "emailverifier.py"), str(input_path_verify)]
                if not smtp_verify_emails:
                    cmd_verify.append("--no-smtp")
                if verify_debug:
                    cmd_verify.append("--debug")
                
                log_verify("$ " + " ".join(cmd_verify))
                stream_process(cmd_verify, PROJECT_DIR, log_verify)
                
                # Check for output file
                base_name = input_path_verify.stem
                output_path_verify = input_path_verify.parent / f"{base_name}_verified{input_path_verify.suffix}"
                
                if output_path_verify.exists():
                    with open(output_path_verify, "rb") as f:
                        verify_download.download_button(
                            label="Download Verified Emails Excel",
                            data=f.read(),
                            file_name=output_path_verify.name,
                            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        )
                    st.success("Email verification complete!")
                else:
                    st.warning("Verification finished but output file not found. Check logs above.")
            
            else:
                # Handle pasted emails
                if not pasted_emails.strip():
                    st.error("Please paste some emails to verify")
                    st.stop()
                
                log_verify("Processing pasted emails...")
                log_verify(f"SMTP verification: {'Enabled' if smtp_verify_emails else 'Disabled'}")
                
                # Parse pasted emails
                lines = pasted_emails.strip().split('\n')
                email_data = []
                
                for i, line in enumerate(lines, 1):
                    if not line.strip():
                        continue
                    # Split by comma and clean up
                    emails_in_line = [email.strip() for email in line.split(',')]
                    email_data.append({
                        'Row': i,
                        'Email': ', '.join(emails_in_line),
                        'Emails_List': emails_in_line
                    })
                
                if not email_data:
                    st.error("No valid emails found in the pasted text")
                    st.stop()
                
                log_verify(f"Found {len(email_data)} rows with emails")
                
                # Create a temporary Excel file for processing
                temp_df = pd.DataFrame(email_data)
                temp_file_path = WORK_DIR / f"temp_emails_{uuid.uuid4().hex[:8]}.xlsx"
                temp_df.to_excel(temp_file_path, index=False)
                
                try:
                    # Run email verification on the temp file
                    cmd_verify = [sys.executable, str(PROJECT_DIR / "emailverifier.py"), str(temp_file_path)]
                    if not smtp_verify_emails:
                        cmd_verify.append("--no-smtp")
                    if verify_debug:
                        cmd_verify.append("--debug")
                    
                    log_verify("$ " + " ".join(cmd_verify))
                    stream_process(cmd_verify, PROJECT_DIR, log_verify)
                    
                    # Check for output file
                    base_name = temp_file_path.stem
                    output_path_verify = temp_file_path.parent / f"{base_name}_verified{temp_file_path.suffix}"
                    
                    if output_path_verify.exists():
                        with open(output_path_verify, "rb") as f:
                            verify_download.download_button(
                                label="Download Verified Emails Excel",
                                data=f.read(),
                                file_name="verified_emails.xlsx",
                                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                            )
                        st.success("Email verification complete!")
                        
                        # Show preview of results
                        result_df = pd.read_excel(output_path_verify)
                        st.subheader("Verification Results Preview")
                        st.dataframe(result_df.head(10), use_container_width=True)
                        
                        if len(result_df) > 10:
                            st.caption(f"Showing first 10 rows of {len(result_df)} total rows")
                    else:
                        st.warning("Verification finished but output file not found. Check logs above.")
                
                finally:
                    # Clean up temp file
                    if temp_file_path.exists():
                        temp_file_path.unlink()

# Runs History Tab
with tab3:
    st.subheader("Previous Runs")
    st.caption("View and download files from previous pipeline runs")
    
    runs = get_runs_history()
    
    if not runs:
        st.info("No previous runs found. Run a pipeline to see results here.")
    else:
        for run in runs:
            with st.expander(f"Run {run['id']} - {run['created'].strftime('%Y-%m-%d %H:%M:%S')}", expanded=False):
                st.write(f"**Created:** {run['created'].strftime('%Y-%m-%d %H:%M:%S')}")
                st.write(f"**Files:** {len(run['files'])}")
                
                if run['files']:
                    st.write("**Available files:**")
                    for file_info in run['files']:
                        col1, col2, col3 = st.columns([3, 1, 1])
                        with col1:
                            st.write(f"📄 {file_info['name']}")
                        with col2:
                            st.write(f"{file_info['size']:,} bytes")
                        with col3:
                            if file_info['path'].exists():
                                with open(file_info['path'], "rb") as f:
                                    st.download_button(
                                        "Download",
                                        data=f.read(),
                                        file_name=file_info['name'],
                                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" if file_info['name'].endswith('.xlsx') else "text/csv",
                                        key=f"download_{run['id']}_{file_info['name']}"
                                    )
                else:
                    st.write("No files found in this run.")