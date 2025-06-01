# Metasploit Exploit CVE Coverage

## 📊 Daily Updated List of Metasploit Exploits Mapped to CVE IDs

This repository provides a **daily, automatically updated JSON dataset** detailing which exploits within the [Metasploit Framework](https://github.com/rapid7/metasploit-framework) are associated with specific Common Vulnerabilities and Exposures (CVE) identifiers.

It leverages a GitHub Actions workflow to regularly traverse the `modules/exploits` directory of the official Metasploit Framework repository. It parses each exploit module to extract all referenced CVE IDs, compiling them into a single, sorted, and easily consumable JSON file.

### Why is this useful?

* **Vulnerability Management:** Quickly identify if a known CVE has a publicly available Metasploit exploit, which can significantly impact its risk profile and prioritization for patching.
* **Threat Intelligence:** Gain insights into Metasploit's coverage of vulnerabilities over time.
* **Security Research:** A convenient dataset for analyzing trends in exploit development and vulnerability weaponization.
* **Automation & Integration:** The JSON output is structured for easy integration into other security tools, scripts, or dashboards for automated vulnerability tracking and exploit awareness.
* **Situational Awareness:** For defenders, this provides an immediate understanding of which vulnerabilities might be actively targeted using readily available tools.

---

### What you'll find here:

* **`metasploit_cves.json`**: The core output file, containing:
    * `last_updated_utc`: The UTC timestamp of the last successful update.
    * `total_exploits_with_cves`: The total count of unique CVEs found across all Metasploit exploit modules.
    * `cves`: A sorted array of unique CVE IDs (e.g., `["CVE-1999-0001", "CVE-2000-0002", ...]`).

---

### How it works:

1.  **Automated Daily Scan:** A GitHub Actions workflow runs daily (or can be manually triggered).
2.  **Metasploit Clone:** The workflow temporarily clones the latest `rapid7/metasploit-framework` repository.
3.  **CVE Extraction:** A Python script iterates through all Ruby exploit modules (`.rb` files) within `modules/exploits`, using regular expressions to identify and extract CVE IDs from the module metadata.
4.  **JSON Generation:** The extracted, unique CVEs are compiled into the `metasploit_cves.json` file.
5.  **Auto-Commit:** The generated JSON file is automatically committed back to this repository, ensuring it's always up-to-date with the latest Metasploit development.

---

### Get Started:

Simply clone this repository or access the `metasploit_cves.json` file directly to integrate this data into your projects.
