#!/usr/bin/env python3
"""
Metasploit Module CVE Extractor
Extracts detailed module information including CVEs, metadata, and usage commands.
"""

import os
import re
import json
from datetime import datetime
from pathlib import Path

# Patterns for extraction
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

def extract_module_metadata(content):
    """Extract metadata from module content."""
    metadata = {}
    
    # Extract Name
    name_match = re.search(r"'Name'\s*=>\s*'([^']+)'", content)
    metadata['name'] = name_match.group(1) if name_match else "Unknown"
    
    # Extract Description (handles both %q{} and '' formats)
    desc_match = re.search(r"'Description'\s*=>\s*%q\{([^}]+)\}|'Description'\s*=>\s*'([^']+)'", content, re.DOTALL)
    if desc_match:
        desc = (desc_match.group(1) or desc_match.group(2) or "").strip()
        # Clean up multi-line descriptions
        desc = re.sub(r'\s+', ' ', desc)
        metadata['description'] = desc
    else:
        metadata['description'] = ""
    
    # Extract Author(s) - Fixed to handle tuples correctly
    authors = []
    author_section = re.search(r"'Author'\s*=>\s*\[([^\]]+)\]", content, re.DOTALL)
    if author_section:
        author_str = author_section.group(1)
        # Extract all quoted strings
        author_matches = re.findall(r"'([^']+)'|\"([^\"]+)\"", author_str)
        for match in author_matches:
            # match is a tuple like ('value', '') or ('', 'value')
            author = match[0] if match[0] else match[1]
            if author.strip():
                authors.append(author.strip())
    metadata['authors'] = authors
    
    # Extract Rank
    rank_match = re.search(r"'Rank'\s*=>\s*(\w+)", content)
    metadata['rank'] = rank_match.group(1) if rank_match else "Unknown"
    
    # Extract Platform - Fixed to handle both array and string formats
    platforms = []
    platform_match = re.search(r"'Platform'\s*=>\s*\[([^\]]+)\]|'Platform'\s*=>\s*'([^']+)'", content)
    if platform_match:
        platform_str = platform_match.group(1) or platform_match.group(2)
        # Extract all quoted strings
        platform_matches = re.findall(r"'([^']+)'|\"([^\"]+)\"", platform_str)
        for match in platform_matches:
            # match is a tuple like ('value', '') or ('', 'value')
            platform = match[0] if match[0] else match[1]
            if platform.strip():
                platforms.append(platform.strip())
    metadata['platform'] = platforms
    
    # Extract Targets
    targets = []
    target_section = re.search(r"'Targets'\s*=>\s*\[(.*?)\]", content, re.DOTALL)
    if target_section:
        # Extract target names (first element of each target array)
        target_matches = re.findall(r"\[\s*'([^']+)'", target_section.group(1))
        targets = target_matches[:5]  # Limit to first 5 targets
    metadata['targets'] = targets
    
    # Extract Privileged requirement
    priv_match = re.search(r"'Privileged'\s*=>\s*(true|false)", content)
    metadata['privileged'] = priv_match.group(1) == 'true' if priv_match else False
    
    # Extract DisclosureDate
    date_match = re.search(r"'DisclosureDate'\s*=>\s*'([^']+)'", content)
    metadata['disclosure_date'] = date_match.group(1) if date_match else ""
    
    # Extract References
    references = []
    ref_section = re.search(r"'References'\s*=>\s*\[(.*?)\]", content, re.DOTALL)
    if ref_section:
        ref_matches = re.findall(r"\[\s*'([^']+)',\s*'([^']+)'\s*\]", ref_section.group(1))
        references = [{'type': r[0], 'value': r[1]} for r in ref_matches]
    metadata['references'] = references
    
    return metadata

def generate_usage_commands(module_path, metadata):
    """Generate usage commands for the module."""
    commands = []
    
    # Basic usage
    commands.append(f"use {module_path}")
    commands.append("show options")
    
    # Only show targets for exploit modules
    if module_path.startswith('exploit'):
        commands.append("show targets")
    
    # Common options based on module type
    if '/http/' in module_path or '/https/' in module_path:
        commands.append("set RHOSTS <target>")
        commands.append("set RPORT <port>")
        if '/ssl/' in module_path or '/https/' in module_path:
            commands.append("set SSL true")
    elif '/smb/' in module_path or '/windows/' in module_path:
        commands.append("set RHOSTS <target>")
        commands.append("set SMBUser <username>")
        commands.append("set SMBPass <password>")
    elif '/ssh/' in module_path:
        commands.append("set RHOSTS <target>")
        commands.append("set USERNAME <username>")
        commands.append("set PASSWORD <password>")
    else:
        commands.append("set RHOSTS <target>")
    
    # Add LHOST for exploits (not for auxiliary or post modules)
    if module_path.startswith('exploit'):
        commands.append("set LHOST <your_ip>")
        commands.append("set LPORT <your_port>")
        commands.append("set PAYLOAD <payload>")
    
    # Add target selection if multiple targets
    if metadata.get('targets') and len(metadata['targets']) > 1:
        commands.append("set TARGET <target_index>")
    
    # Execute
    if module_path.startswith('exploit'):
        commands.append("exploit")
    else:
        commands.append("run")
    
    return commands

def extract_module_info(module_path, msf_root):
    """Extract complete information from a Metasploit module file."""
    try:
        with open(module_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Extract CVEs
        cves = set(CVE_PATTERN.findall(content))
        cves = [cve.upper() for cve in cves]
        
        if not cves:
            return None
        
        # Get relative path from modules/exploits/
        rel_path = str(module_path).replace(str(msf_root) + '/modules/', '').replace('.rb', '')
        
        # Extract metadata
        metadata = extract_module_metadata(content)
        
        # Generate usage commands
        usage_commands = generate_usage_commands(rel_path, metadata)
        
        module_info = {
            "module_path": rel_path,
            "name": metadata['name'],
            "description": metadata['description'],
            "authors": metadata['authors'],
            "rank": metadata['rank'],
            "platform": metadata['platform'],
            "targets": metadata['targets'],
            "privileged": metadata['privileged'],
            "disclosure_date": metadata['disclosure_date'],
            "references": metadata['references'],
            "github_url": f"https://github.com/rapid7/metasploit-framework/blob/master/modules/{rel_path}.rb",
            "raw_url": f"https://raw.githubusercontent.com/rapid7/metasploit-framework/master/modules/{rel_path}.rb",
            "usage_commands": usage_commands
        }
        
        return cves, module_info
        
    except Exception as e:
        print(f"Error processing {module_path}: {e}")
        return None

def main():
    """Main execution function."""
    msf_root = Path("metasploit-framework")
    modules_dir = msf_root / "modules"
    
    if not modules_dir.exists():
        print(f"Error: {modules_dir} not found. Make sure Metasploit Framework is cloned.")
        return 1
    
    # Scan these module types
    module_types = ['exploits', 'auxiliary', 'post']
    
    cve_modules = {}
    total_modules = 0
    modules_with_cves = 0
    
    print("Scanning Metasploit modules...")
    
    # Walk through all module types
    for module_type in module_types:
        module_type_dir = modules_dir / module_type
        if not module_type_dir.exists():
            print(f"  Warning: {module_type_dir} not found, skipping...")
            continue
        
        print(f"  Scanning {module_type} modules...")
        
        for module_file in module_type_dir.rglob("*.rb"):
            total_modules += 1
            if total_modules % 100 == 0:
                print(f"    Processed {total_modules} modules...")
            
            result = extract_module_info(module_file, msf_root)
            
            if result:
                modules_with_cves += 1
                cves, module_info = result
                
                for cve in cves:
                    if cve not in cve_modules:
                        cve_modules[cve] = {"modules": []}
                    cve_modules[cve]["modules"].append(module_info)
    
    print(f"\n+ Scanned {total_modules} total modules")
    print(f"+ Found {modules_with_cves} modules with CVE references")
    print(f"+ Identified {len(cve_modules)} unique CVEs")
    
    # Calculate total module-CVE mappings
    total_mappings = sum(len(data["modules"]) for data in cve_modules.values())
    
    # Generate output
    output = {
        "metadata": {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "source": "Metasploit Framework",
            "source_url": "https://github.com/rapid7/metasploit-framework",
            "total_modules_scanned": total_modules,
            "modules_with_cves": modules_with_cves,
            "total_cves": len(cve_modules),
            "total_module_cve_mappings": total_mappings
        },
        "cves": cve_modules
    }
    
    # Write to file
    output_file = "metasploit_cves.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    
    print(f"\n+ Successfully generated {output_file}")
    print(f"  - Total CVEs: {len(cve_modules)}")
    print(f"  - Total module-CVE mappings: {total_mappings}")
    
    # Print sample entry
    if cve_modules:
        sample_cve = list(cve_modules.keys())[0]
        print(f"\nSample entry ({sample_cve}):")
        print(f"  Modules: {len(cve_modules[sample_cve]['modules'])}")
        if cve_modules[sample_cve]['modules']:
            sample_module = cve_modules[sample_cve]['modules'][0]
            print(f"  Module: {sample_module['module_path']}")
            print(f"  Name: {sample_module['name']}")
            print(f"  Authors: {', '.join(sample_module['authors'])}")
            print(f"  Rank: {sample_module['rank']}")
    
    return 0

if __name__ == "__main__":
    exit(main())
