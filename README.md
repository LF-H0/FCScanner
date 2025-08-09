# 🕵️‍♂️ Ultimate Web Recon Tool

[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/LF-H0/FCScanner.pulls)

> Professional reconnaissance tool for web security assessment and bug bounty hunting

![](demo.gif)

The Ultimate Web Recon Tool is a comprehensive security scanner that combines crawling and fuzzing capabilities to identify attack surfaces, hidden endpoints, and sensitive information leaks.

## ✨ Features

- **Smart Website Crawler**
  - JavaScript-aware crawling
  - Subdomain exclusion
  - Secret scanning in JS files
  - URL categorization
- **Advanced Fuzzer**
  - Directory/File/Subdomain discovery
  - WAF evasion techniques
  - Dynamic wordlist selection
  - Wildcard DNS detection
- **Professional Output**
  - Color-coded results
  - Progress tracking
  - Categorized findings
- **Performance Optimized**
  - Multi-threaded processing
  - Jittered request timing
  - Session rotation

## ⚙️ Installation

```bash
https://github.com/LF-H0/FCScanner.git
cd FCScanner
pip install -r requirements.txt
python main.py -h
