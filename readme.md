<h1 align="center">$ cWee</h1>
<h4 align="center">Advanced CVE Searching</h4>

<p align="center">
  <img src="https://i.ibb.co/Cs6vQ77W/image.png" alt="cWee Demo" width="700"/>
</p>

## cWee
**cWee** is an advanced CVE (Common Vulnerabilities and Exposures) searching tool, built on top of the powerful [nvdlib](https://nvdlib.com/en/latest/v2/CVEv2.html) library.

It allows security researchers, penetration testers, and enthusiasts to quickly search for vulnerabilities with **multiple filters** such as date range, product, vendor, severity, and more — making vulnerability research faster and more efficient.


## Why cWee?
- **Simplified CVE Hunting** – Instead of writing custom queries with `nvdlib` or struggling with the NVD web UI, cWee gives you a clean interface with multiple filters in one place.
- **Faster Research Workflow** – Apply filters like **date range, vendor, product, severity, and keyword** in a single command to instantly narrow results.
- **Built for Security Researchers** – Whether you’re analyzing vulnerabilities for red teaming, bug bounties, or academic research, cWee is designed to save time.
- **Stay Up to Date** – Track recent vulnerabilities without manually browsing the NVD website.
- **Extensible & Lightweight** – Powered by `nvdlib`, but wrapped into a practical tool that you can extend with your own scripts.
## Usage
cWee is live and accessible via the web! 
visit:
```
https://cwee.awwfensive.site/
```
### To do
- **Multiple Filter Search** – Support applying more than one filter in a single query.
-  **Multiple Keyword Search** – Allow inputs like `go, web` to return CVEs related to Go-based web applications (currently not supported directly in `nvdlib`).
-  **Sorting by Date** – Add ascending/descending sort options for results.


# Credits 
- [nvdlib](https://nvdlib.com/en/latest/v2/CVEv2.html) – Python wrapper for NVD API.  
- [NVD](https://nvd.nist.gov/) – Source of CVE data.  
