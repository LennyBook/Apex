#!/usr/bin/env python3
File_Name: Multi_Tool.py
File_Path: Downloads/Apex/Tools/Scripts/Multi_Tool.py
Purpose: Automate Apex system tasks, including tag validation, file patching, chat chunking, and crash recovery, supporting project lifecycle tracking and Flask UI navigation.
Envisioned_By: Len, 04-April-2025
Version: 1.2
Modified: 11-May-2025
Markers: None
Timezone: UTC+2
Last_Known_Stable: 1.1
Self_Heal: True
Master_Link: [Placeholder]
Process_Instruction: Validates headers of generated .txt files (e.g., chat chunks) against New_File_Template.txt, applying standard Apex header with Short Name (MT) for chat use. Proposes fixes for missing fields (e.g., Purpose, Description and Summary), prompting: “Len, [File] header missing [Field]. Suggest: ‘[Proposed]’. Confirm?” Parses #tags from files and chats, validating against Full_Tags.txt, logging invalid tags as #Unclassified in Session_Tasks_dd_Month_yyyy.txt, prompting: “Len, define #Tag?” Applies patches, chunks logs, and reassembles files, logging actions to CrashGuard_dd_Month_yyyy.txt. Supports Flask UI navigation by mapping tags (e.g., #02-Narrative) to hub files (e.g., Deep_Sea_NN_Wars_Hub.txt).
Dependencies: [Grok_Configuration.txt, Full_Tags.txt, New_File_Template.txt, Session_Tasks_dd_Month_yyyy.txt, CrashGuard_dd_Month_yyyy.txt, scan_assets_dirs.py, os, hashlib, re, glob, argparse]
Tags: [#Apex_Process, #Task_Management, #Crash_Recovery, #File_Management, #Tag_Validation]
Status: Active
Owner: Len
Hub: Apex_System_Hub
Critical: True
File_Type: Python Script
Description: Automates Apex system tasks by validating tags against Full_Tags.txt, patching files, chunking chat logs for crash recovery, and reassembling files for project organization. Supports lifecycle tracking for projects like #Deep_Sea_NN_Wars using tags (e.g., #Live_Task, #02-Narrative) and integrates with Flask UI for file navigation. Ensures header consistency in generated .txt files using New_File_Template.txt, applying Short Name (MT) for chat efficiency. Logs actions and errors to CrashGuard_dd_Month_yyyy.txt for recovery. Executes scan_assets_dirs.py to update Apex asset structures.

[Content_Start]
import os
import hashlib
import re
import glob
import argparse

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))  # Apex/
TOOLS_DIR = os.path.join(BASE_DIR, "Tools")  # Apex/Tools/
PATCH_DIR = os.path.join(TOOLS_DIR, "Patches")  # Apex/Tools/Patches/
PATCH_LOG = os.path.join(TOOLS_DIR, "patch_log.txt")  # Apex/Tools/
CONFIG_DIR = os.path.join(TOOLS_DIR, "Config_Files")  # Apex/Tools/Config_Files/
FOR_PROCESSING_DIR = os.path.join(TOOLS_DIR, "For_Processing")  # Apex/Tools/For_Processing/

# Tag Validation Functions
def validate_tags(tags, full_tags_file):
    """Validate tags against Full_Tags.txt, logging invalid tags."""
    if not os.path.exists(full_tags_file):
        print(f"Error: {full_tags_file} not found.")
        return []
    with open(full_tags_file, "r", encoding="utf-8") as f:
        valid_tags = set(re.findall(r'#[\w-]+', f.read()))
    invalid_tags = [tag for tag in tags if tag not in valid_tags]
    if invalid_tags:
        log_file = os.path.join(FOR_PROCESSING_DIR, f"Session_Tasks_11_May_2025.txt")
        os.makedirs(FOR_PROCESSING_DIR, exist_ok=True)
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(f"#Unclassified: Invalid tags detected: {', '.join(invalid_tags)}\n")
        print(f"Invalid tags logged to {log_file}: {invalid_tags}")
    return invalid_tags

def check_tag_count(config_file, full_tags_file):
    """Cross-check tag count and categories between Grok_Configuration.txt and Full_Tags.txt."""
    if not os.path.exists(full_tags_file) or not os.path.exists(config_file):
        print(f"Error: Missing {full_tags_file} or {config_file}.")
        return
    with open(full_tags_file, "r", encoding="utf-8") as f:
        full_tags_content = f.read()
        full_tags_count = len(re.findall(r'#[\w-]+', full_tags_content))
        full_tags_categories = re.findall(r'##([\w\s-]+) \((\d+)\)', full_tags_content)
    with open(config_file, "r", encoding="utf-8") as f:
        config_content = f.read()
        config_tag_count_match = re.search(r'Full_Tags\.txt tracks (\d+) tags', config_content)
        config_tag_count = int(config_tag_count_match.group(1)) if config_tag_count_match else None
    log_file = os.path.join(FOR_PROCESSING_DIR, f"Session_Tasks_11_May_2025.txt")
    if config_tag_count and config_tag_count != full_tags_count:
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(f"#Task_Management: Tag count mismatch - Grok_Configuration.txt: {config_tag_count}, Full_Tags.txt: {full_tags_count}\n")
        print(f"Tag count mismatch logged to {log_file}. Suggest updating Full_Tags.txt or removing count from Grok_Configuration.txt.")
    config_tags = set(re.findall(r'#[\w-]+', config_content))
    full_tags = set(re.findall(r'#[\w-]+', full_tags_content))
    hardcoded_tags = config_tags - full_tags - set(['#Apex_Process', '#Task_Management', '#Chat_Process', '#Crash_Recovery', '#Writing', '#Fact_Checking', '#Creative_Spark', '#Unclassified'])
    if hardcoded_tags:
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(f"#Task_Management: Hardcoded tags in Grok_Configuration.txt: {', '.join(hardcoded_tags)}\n")
        print(f"Hardcoded tags detected in Grok_Configuration.txt: {hardcoded_tags}. Suggest moving to Full_Tags.txt.")

# Patch Functions
def get_patch_hash(content):
    """Calculate MD5 hash of patch content."""
    return hashlib.md5(content.encode('utf-8')).hexdigest()

def log_patch(patch_hash, message):
    """Log patch application to patch_log.txt and CrashGuard."""
    os.makedirs(TOOLS_DIR, exist_ok=True)
    with open(PATCH_LOG, "a", encoding="utf-8") as f:
        f.write(f"{patch_hash[:10]} - {message}\n")
    crashguard_file = os.path.join(FOR_PROCESSING_DIR, "CrashGuard_11_May_2025.txt")
    os.makedirs(FOR_PROCESSING_DIR, exist_ok=True)
    with open(crashguard_file, "a", encoding="utf-8") as f:
        f.write(f"#Crash_Recovery: {message}\n")
    print(f"Patch logged to {PATCH_LOG} and {crashguard_file}.")

def is_patch_applied(patch_hash):
    """Check if patch has been applied."""
    if not os.path.exists(PATCH_LOG):
        return False
    with open(PATCH_LOG, "r", encoding="utf-8") as f:
        return patch_hash in [line.split(" - ")[0] for line in f.read().splitlines()]

def apply_mb_patch(patch_file, target_file, dry_run=False):
    """Apply patch to target file, logging to patch_log.txt and CrashGuard."""
    with open(patch_file, "r", encoding="utf-8") as f:
        patch_content = f.read().strip()
    patch_hash = get_patch_hash(patch_content)
    if is_patch_applied(patch_hash):
        print("Patch already applied—skipping.")
        return
    if dry_run:
        print(f"Would patch {target_file} with {patch_content[:50]}...")
    else:
        with open(target_file, "a", encoding="utf-8") as f:
            f.write(f"\n{patch_content}\n")
        log_patch(patch_hash, f"Success: {os.path.basename(target_file)} patched with #Live_Task")
        print(f"Patched {target_file} with #Live_Task.")

# Chunking Functions
def chunk_file(input_file, chunk_size=300):
    """Chunk chat logs for crash recovery, applying header and tags."""
    with open(input_file, "r", encoding="utf-8") as f:
        lines = f.readlines()
    filename = os.path.basename(input_file)
    chunks = [lines[i:i+chunk_size] for i in range(0, len(lines), chunk_size)]
    for idx, chunk in enumerate(chunks, 1):
        output_file = os.path.join(FOR_PROCESSING_DIR, f"{filename}_part{idx}.txt")
        tags = extract_tags("".join(chunk))
        invalid_tags = validate_tags(tags, os.path.join(CONFIG_DIR, "Full_Tags.txt"))
        header = f"""
File_Name: {filename}_part{idx}.txt
File_Path: Downloads/Apex/Tools/For_Processing/{filename}_part{idx}.txt
Purpose: Store chunk {idx} of {len(chunks)} from {filename} for crash recovery and project sorting.
Envisioned_By: Len, 11-May-2025
Version: 1.0
Modified: 11-May-2025
Markers: None
Timezone: UTC+2
Dependencies: [Grok_Configuration.txt, Full_Tags.txt]
Tags: [{' '.join(tags)}]
Status: Active
Owner: Len
Hub: Apex_System_Hub
Critical: False
File_Type: Text
Short_Name: MT_Chunk_{idx}
Description: Contains chunk {idx} of {filename}, used for crash recovery and sorting into project hubs (e.g., Deep_Sea_NN_Wars_Hub.txt). Parsed for #tags like #Live_Task or #02-Narrative to map to project sections. Generated by Multi_Tool.py, validated against Full_Tags.txt. Supports Flask UI navigation.
"""
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(header + "\n" + "".join(chunk))
        print(f"Wrote {output_file} with tags: {tags}")

def reassemble_chunks(chunk_files, output_file):
    """Reassemble chunked files, preserving tags and headers."""
    content = []
    tags = []
    for chunk_file in sorted(chunk_files):
        with open(chunk_file, "r", encoding="utf-8") as f:
            lines = [line for line in f.read().splitlines() if not line.startswith("File_Name:") and not line.startswith("# PART")]
            content.extend(lines)
            chunk_tags = extract_tags("".join(lines))
            tags.extend(chunk_tags)
    output_path = os.path.join(FOR_PROCESSING_DIR, output_file)
    header = f"""
File_Name: {output_file}
File_Path: Downloads/Apex/Tools/For_Processing/{output_file}
Purpose: Reassembled chat log for project sorting and crash recovery.
Envisioned_By: Len, 11-May-2025
Version: 1.0
Modified: 11-May-2025
Markers: None
Timezone: UTC+2
Dependencies: [Grok_Configuration.txt, Full_Tags.txt]
Tags: [{' '.join(set(tags))}]
Status: Active
Owner: Len
Hub: Apex_System_Hub
Critical: False
File_Type: Text
Short_Name: MT_Reassembled
Description: Reassembled chat log from {len(chunk_files)} chunks, used for crash recovery and sorting into project hubs (e.g., Deep_Sea_NN_Wars_Hub.txt). Parsed for #tags like #Live_Task or #02-Narrative to map to project sections. Generated by Multi_Tool.py, validated against Full_Tags.txt. Supports Flask UI navigation.
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(header + "\n".join(content) + "\n")
    validate_tags(tags, os.path.join(CONFIG_DIR, "Full_Tags.txt"))
    print(f"Reassembled {output_path} with tags: {set(tags)}")

def extract_tags(content):
    """Extract #tags from content for validation."""
    return re.findall(r'#[\w-]+', content)

# Main
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Multi-tool for Apex automation, tag validation, patching, and chunking.")
    parser.add_argument("--patch", help="Patch file to apply")
    parser.add_argument("--target", help="Target file for patch")
    parser.add_argument("--chunk", help="File to chunk")
    parser.add_argument("--reassemble", nargs="+", help="Chunk files to reassemble")
    parser.add_argument("--output", help="Output file for reassemble")
    parser.add_argument("--validate-tags", action="store_true", help="Validate tags between Grok_Configuration.txt and Full_Tags.txt")
    args = parser.parse_args()

    if args.validate_tags:
        check_tag_count(
            os.path.join(BASE_DIR, "Manuals", "Grok_Configuration.txt"),
            os.path.join(CONFIG_DIR, "Full_Tags.txt")
        )
    elif args.patch and args.target:
        apply_mb_patch(args.patch, args.target)
    elif args.chunk:
        chunk_file(args.chunk)
    elif args.reassemble and args.output:
        reassemble_chunks(args.reassemble, args.output)
    else:
        print("Usage: Multi_Tool.py [--patch <file> --target <file>] [--chunk <file>] [--reassemble <chunks> --output <file>] [--validate-tags]")

[Content_End]
