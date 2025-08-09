import requests
from urllib.parse import urlparse, urljoin, urlunparse, unquote
from bs4 import BeautifulSoup
from collections import defaultdict
import os
import tldextract
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import re
import signal
import sys
import html
import codecs
import threading
from colorama import Fore, Style, init
import hashlib

# Initialize colorama
init(autoreset=True)

class SecretScanner:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.results = []
        self.stats = {
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0,
            'total_files': 0,
            'unique_types': set(),
            'start_time': time.time()
        }
        self.grouped_findings = defaultdict(lambda: {
            'severity': '',
            'type': '',
            'urls': set(),
            'context': ''
        })
        
    def get_severity(self, pattern_name):
        SEVERITY_LEVELS = {
            'rsa_private': 'critical',
            'aws_secret_key': 'critical',
            'stripe_standard': 'critical',
            'github_token': 'critical',
            'google_api': 'high',
            'slack_token': 'high',
            'twilio_api': 'high',
            'jwt_token': 'high',
            'hardcoded_creds': 'high',
            'aws_access_key': 'medium',
            'basic_auth': 'medium',
        }
        return SEVERITY_LEVELS.get(pattern_name, 'medium')
    
    def get_context(self, match, content, context_size=300):
        start = max(0, match.start() - context_size)
        end = min(len(content), match.end() + context_size)
        context = content[start:end].strip()
        return context

    def is_valid_secret(self, pattern_name, secret_value, context):
        if pattern_name == 'aws_secret_key' and ('/' in secret_value or '.' in secret_value):
            return False
        if pattern_name == 'jwt_token' and secret_value.count('.') != 2:
            return False
        return True

    def scan_content(self, content, url):
        SENSITIVE_PATTERNS = {
            'google_api': r'\bAIza[0-9A-Za-z\-_]{35}\b',
            'aws_access_key': r'\b(AKIA|ASIA)[A-Z0-9]{16}\b',
            'aws_secret_key': r'(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])',
            'github_token': r'\b(ghp|gho|ghu|ghs|github_pat)_[a-zA-Z0-9_]{36,255}\b',
            'slack_token': r'\bxox[baprs]-[0-9a-zA-Z\-]{10,48}\b',
            'stripe_standard': r'\b(sk|pk)_(test|live)_[0-9a-zA-Z]{24}\b',
            'twilio_api': r'\bSK[0-9a-fA-F]{32}\b',
            'jwt_token': r'\bey[0-9A-Za-z\-_=]+\.[0-9A-Za-z\-_=]+\.?[0-9A-Za-z\-_+/=]{20,}\b',
            'basic_auth': r'\b[Bb]asic\s+[a-zA-Z0-9=:_\+\/-]{20,}\b',
            'rsa_private': r'-----BEGIN RSA PRIVATE KEY-----',
            'hardcoded_creds': r'\b(?:[Pp]assword|[Pp]wd|[Pp]asswd|[Ss]ecret|[Kk]ey|[Tt]oken|[Aa]uth)\s*[:=]\s*[\'"][^\'"]{8,100}[\'"]\b',
        }
        
        findings = []
        
        for pattern_name, pattern in SENSITIVE_PATTERNS.items():
            try:
                for match in re.finditer(pattern, content):
                    secret_value = match.group(0)
                    context = self.get_context(match, content)
                    
                    if not self.is_valid_secret(pattern_name, secret_value, context):
                        continue
                    
                    severity = self.get_severity(pattern_name)
                    key = (secret_value, pattern_name)
                    
                    self.stats['unique_types'].add(pattern_name)
                    if severity == 'critical': self.stats['critical_count'] += 1
                    elif severity == 'high': self.stats['high_count'] += 1
                    elif severity == 'medium': self.stats['medium_count'] += 1
                    else: self.stats['low_count'] += 1
                    
                    if key not in self.grouped_findings:
                        self.grouped_findings[key] = {
                            'severity': severity,
                            'type': pattern_name,
                            'urls': set(),
                            'context': context
                        }
                    self.grouped_findings[key]['urls'].add(url)
                    
                    findings.append({
                        'type': pattern_name,
                        'matched': secret_value,
                        'severity': severity,
                        'context': context
                    })
            except Exception as e:
                if self.verbose:
                    print(f"[!] Error scanning for {pattern_name}: {str(e)}")
        
        return findings

    def fetch_resource(self, url):
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
            response = requests.get(url, headers=headers, verify=False, timeout=20)
            response.raise_for_status()
            return response.text
        except Exception as e:
            if self.verbose:
                print(f"[!] Error fetching {url}: {str(e)}")
            return None

    def process_resource(self, resource):
        try:
            content = self.fetch_resource(resource)
            if content is None:
                return None
                
            self.stats['total_files'] += 1
            findings = self.scan_content(content, resource)
            if findings:
                return {'url': resource, 'findings': findings}
            return None
        except Exception as e:
            if self.verbose:
                print(f"[!] Error processing {resource}: {str(e)}")
            return None

    def generate_report(self):
        print(f"\n{Fore.CYAN}{Style.BRIGHT}===== SECRET FINDER REPORT ====={Style.RESET_ALL}")
        
        if not self.grouped_findings:
            print(f"{Fore.YELLOW}No secrets found{Style.RESET_ALL}")
            return
            
        for (secret_value, pattern_name), group in self.grouped_findings.items():
            severity = group['severity']
            if severity == 'critical': color = Fore.MAGENTA
            elif severity == 'high': color = Fore.RED
            elif severity == 'medium': color = Fore.YELLOW
            else: color = Fore.GREEN
                
            print(f"\n{color}{Style.BRIGHT}[{severity[0].upper()}] {pattern_name.replace('_', ' ').title()}:{Style.RESET_ALL}")
            print(f"  {Style.BRIGHT}{secret_value}{Style.RESET_ALL}")
            
            print(f"  {Fore.BLUE}Found in:{Style.RESET_ALL}")
            for url in group['urls']:
                print(f"    - {url}")
            
            if self.verbose and group['context']:
                print(f"  {Fore.BLUE}Context:{Style.RESET_ALL}")
                print(f"    {group['context'][:300]}{'...' if len(group['context']) > 300 else ''}")
        
        print(f"\n{Fore.CYAN}{Style.BRIGHT}===== SCAN SUMMARY ====={Style.RESET_ALL}")
        print(f"Files scanned: {Style.BRIGHT}{self.stats['total_files']}{Style.RESET_ALL}")
        total_findings = self.stats['critical_count'] + self.stats['high_count'] + self.stats['medium_count'] + self.stats['low_count']
        print(f"Total findings: {Style.BRIGHT}{total_findings}{Style.RESET_ALL}")
        print(f"Critical: {Fore.MAGENTA}{Style.BRIGHT}{self.stats['critical_count']}{Style.RESET_ALL}")
        print(f"High: {Fore.RED}{Style.BRIGHT}{self.stats['high_count']}{Style.RESET_ALL}")
        print(f"Medium: {Fore.YELLOW}{Style.BRIGHT}{self.stats['medium_count']}{Style.RESET_ALL}")
        print(f"Low: {Fore.GREEN}{Style.BRIGHT}{self.stats['low_count']}{Style.RESET_ALL}")
        print(f"Unique types: {Style.BRIGHT}{len(self.stats['unique_types'])}{Style.RESET_ALL}")
        print(f"Duration: {Style.BRIGHT}{self.stats['scan_duration']} seconds{Style.RESET_ALL}")
        print(f"{Fore.CYAN}======================={Style.RESET_ALL}")

    def scan_urls(self, urls):
        if not urls:
            return
            
        if self.verbose:
            print(f"[*] Starting secret scan of {len(urls)} resource(s)")
        
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(self.process_resource, url) for url in urls]
            for future in as_completed(futures):
                if result := future.result():
                    self.results.append(result)
        
        self.stats['scan_duration'] = round(time.time() - self.stats['start_time'], 2)
        self.generate_report()

class WebCrawler:
    def __init__(self, base_url, exclude_extensions=None, jscrawl=False, no_subs=False, scan_secrets=False):
        self.base_url = self.normalize_input_url(base_url)
        self.exclude_extensions = set(ex.lower() for ex in exclude_extensions) if exclude_extensions else set()
        self.jscrawl = jscrawl
        self.no_subs = no_subs
        self.scan_secrets = scan_secrets
        
        # Extract base domain information
        self.base_extract = tldextract.extract(self.base_url)
        self.base_domain = self.base_extract.registered_domain
        
        # Data stores
        self.all_urls = set()
        self.queue = set()
        self.visited = set()
        self.categorized = {
            'params': set(),
            'js': set(),
            'subdomains': set(),
            'extensions': defaultdict(set),
            'js_found_urls': set()  # URLs found in JS content
        }
        
        # Initialize with base URL
        clean_base = self.clean_url(self.base_url)
        self.queue.add(clean_base)
        self.all_urls.add(clean_base)
        
        # Ctrl+C handling
        self.stop_requested = False
        signal.signal(signal.SIGINT, self.handle_signal)
        
        # Lock for thread-safe printing
        self.print_lock = threading.Lock()

    def handle_signal(self, signum, frame):
        """Handle Ctrl+C signal"""
        with self.print_lock:
            print(f"\n{Fore.RED}{Style.BRIGHT}CRAWLING INTERRUPTED BY USER! SAVING PROGRESS...{Style.RESET_ALL}")
        self.stop_requested = True
        raise SystemExit

    def decode_unicode_escapes(self, s):
        r"""Decode unicode escape sequences like \uXXXX in URLs"""
        def replace_unicode(match):
            return codecs.decode(match.group(0), 'unicode_escape')
        return re.sub(r'\\u[0-9a-fA-F]{4}', replace_unicode, s)

    def clean_url(self, url):
        """Normalize and decode URL to handle escape sequences"""
        # First decode JavaScript unicode escapes
        url = self.decode_unicode_escapes(url)
        
        # Decode URL-encoded characters
        decoded = unquote(url)
        
        # Decode HTML entities
        decoded = html.unescape(decoded)
        
        # Normalize URL structure
        parsed = urlparse(decoded)
        cleaned = parsed._replace(fragment='', query='')
        normalized = urlunparse(cleaned).rstrip('/')
        
        return normalized

    def normalize_input_url(self, url):
        """Ensure URL has a scheme"""
        parsed = urlparse(url)
        if parsed.scheme:
            return url
            
        # Try HTTPS first
        try:
            test_url = f"https://{url}"
            response = requests.head(test_url, timeout=5, allow_redirects=True)
            if response.status_code < 400:
                return test_url
        except:
            pass
            
        # If HTTPS fails, try HTTP
        try:
            test_url = f"http://{url}"
            response = requests.head(test_url, timeout=5, allow_redirects=True)
            if response.status_code < 400:
                return test_url
        except:
            pass
            
        # Default to HTTPS if both fail
        return f"https://{url}"

    def is_same_domain(self, url):
        """Check if URL belongs to target domain and respects subdomain exclusion"""
        extracted = tldextract.extract(url)
        
        # Always require matching base domain
        if extracted.registered_domain != self.base_domain:
            return False
            
        # Handle subdomain exclusion
        if self.no_subs:
            # Allow only base domain (no subdomains) or exact base URL subdomain
            base_subdomain = self.base_extract.subdomain
            current_subdomain = extracted.subdomain
            
            # If base URL has a subdomain, allow it and its direct paths
            if base_subdomain:
                return current_subdomain == base_subdomain
            # If base URL has no subdomain, allow only no-subdomain URLs
            return not current_subdomain
            
        return True

    def get_extension(self, url):
        """Extract file extension from URL path"""
        path = urlparse(url).path
        if '.' in path:
            return path.split('.')[-1].split('?')[0].split('#')[0].lower()
        return None

    def should_exclude(self, url):
        """Check if URL has excluded extension"""
        ext = self.get_extension(url)
        return ext in self.exclude_extensions if ext else False

    def is_valid_url(self, url):
        """Validate if string is a proper URL"""
        # Skip URLs with JavaScript code snippets
        if re.search(r'[$\s{},;:]', url):
            return False
            
        # Skip URLs with unusual patterns
        if re.search(r'[{}()]', url):
            return False
            
        # Must have a valid scheme or be relative
        if not (url.startswith(('http://', 'https://', '/'))) and '://' in url:
            return False
            
        # Must contain a valid TLD or path component
        if not re.search(r'\.\w{2,}|/', url):
            return False
            
        return True

    def extract_js_urls(self, js_content, base_url):
        """Extract clean URLs from JavaScript content using robust patterns"""
        found_urls = set()
        
        # Improved regex patterns for cleaner URL extraction
        patterns = [
            r'[\'"](https?://[^\s"\'<>{}()]+)[\'"]',  # Double-quoted absolute URLs
            r'[\'"](/[^\s"\'<>{}()#]+)[\'"]',          # Double-quoted root-relative URLs
            r'[\'"]([^\s"\'<>{}()]+\.[a-z]{2,4})[\'"]' # File references
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, js_content):
                url = match.group(1)
                
                # Skip invalid URLs
                if not self.is_valid_url(url):
                    continue
                
                # Handle relative URLs
                if not url.startswith('http'):
                    if url.startswith('/'):
                        # Root-relative URL
                        url = urljoin(base_url, url)
                    else:
                        # Path-relative URL
                        url = urljoin(base_url + '/', url)
                
                # Clean and normalize the URL
                cleaned_url = self.clean_url(url)
                if self.is_same_domain(cleaned_url) and cleaned_url not in self.all_urls:
                    found_urls.add(cleaned_url)
                    self.categorized['js_found_urls'].add(cleaned_url)
        
        return found_urls

    def categorize_url(self, url):
        """Categorize URL into appropriate groups"""
        parsed = urlparse(url)
        
        # Check for parameters
        if parsed.query:
            self.categorized['params'].add(url)
        
        # Check for JavaScript
        if url.endswith('.js') or '.js?' in url:
            self.categorized['js'].add(url)
        
        # Extract and store subdomain
        extracted = tldextract.extract(url)
        if extracted.subdomain:
            self.categorized['subdomains'].add(extracted.subdomain)
        
        # Store by extension
        ext = self.get_extension(url)
        if ext:
            self.categorized['extensions'][ext].add(url)

    def process_page(self, url):
        """Fetch and parse a single page"""
        try:
            if url in self.visited or self.should_exclude(url) or self.stop_requested:
                return set()
                
            self.visited.add(url)
            
            # Print only if not in jscrawl mode or if it's a JS file
            if not self.jscrawl or (self.jscrawl and (url.endswith('.js') or '.js?' in url)):
                with self.print_lock:
                    print(url)

            response = requests.get(url, timeout=10, allow_redirects=True)
            response.raise_for_status()
            
            # Process final URL after redirects
            final_url = self.clean_url(response.url)
            if final_url != url:
                self.all_urls.add(final_url)
                self.categorize_url(final_url)
            
            content_type = response.headers.get('Content-Type', '').lower()
            new_urls = set()
            
            # Handle JavaScript content extraction
            if self.jscrawl and ('javascript' in content_type or url.endswith('.js')):
                js_urls = self.extract_js_urls(response.text, url)
                for js_url in js_urls:
                    if js_url not in self.all_urls:
                        self.all_urls.add(js_url)
                        self.categorized['js_found_urls'].add(js_url)
                        # Print URLs found in JS content
                        with self.print_lock:
                            print(f"{Fore.YELLOW}{Style.BRIGHT}[+]  {Style.RESET_ALL} {Style.BRIGHT}{js_url}")
            
            # Parse HTML content
            if 'text/html' in content_type:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Find all links
                for tag in soup.find_all(['a', 'link', 'area', 'script', 'img', 'iframe', 'source']):
                    attr = 'href' if tag.name in ['a', 'link', 'area'] else 'src'
                    if tag.name == 'script' and 'src' not in tag.attrs:
                        continue
                    if attr in tag.attrs:
                        absolute_url = urljoin(url, tag[attr])
                        cleaned_url = self.clean_url(absolute_url)
                        
                        # Add valid URLs to processing queue
                        if self.is_same_domain(cleaned_url) and cleaned_url not in self.all_urls:
                            new_urls.add(cleaned_url)
                            self.all_urls.add(cleaned_url)
                            self.categorize_url(cleaned_url)
            
            return new_urls
        except Exception:
            return set()  # Suppress error messages

    def crawl(self):
        """Main crawling function with high-concurrency multi-threading"""
        # Use 50 threads by default for high speed
        executor = ThreadPoolExecutor(max_workers=50)
        try:
            while self.queue and not self.stop_requested:
                futures = {executor.submit(self.process_page, url): url for url in self.queue}
                self.queue = set()
                
                try:
                    for future in as_completed(futures):
                        if self.stop_requested:
                            break
                        new_urls = future.result()
                        if new_urls:
                            self.queue.update(new_urls - self.visited)
                except KeyboardInterrupt:
                    self.stop_requested = True
                    break
        finally:
            executor.shutdown(wait=False)
        
        if not self.stop_requested:
            print(f"\n{Fore.GREEN}{Style.BRIGHT}[ - ] CRAWLING COMPLETED!{Style.RESET_ALL}")
            
        # Run secret scanning if enabled
        if not self.stop_requested and self.scan_secrets:
            self.run_secret_scan()

    def run_secret_scan(self):
        js_urls = self.categorized['js'] | self.categorized['js_found_urls']
        if not js_urls:
            print(f"{Fore.YELLOW}[!] No JavaScript files found for secret scanning{Style.RESET_ALL}")
            return
            
        print(f"\n{Fore.CYAN}{Style.BRIGHT}[ + ] STARTING SECRET SCAN ON {len(js_urls)} JS FILES{Style.RESET_ALL}")
        scanner = SecretScanner(verbose=True)
        scanner.scan_urls(js_urls)

    def save_results(self, output_dir):
        """Save categorized results to files"""
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Save all URLs
        with open(os.path.join(output_dir, "all_urls.txt"), 'w', encoding='utf-8') as f:
            f.write("\n".join(sorted(self.all_urls)))
        
        # Save categorized URLs
        categories = {
            'urls_with_parameters': self.categorized['params'],
            'js_urls': self.categorized['js'],
            'subdomains': self.categorized['subdomains'],
            'js_found_urls': self.categorized['js_found_urls']  # URLs found in JS content
        }
        
        for name, data in categories.items():
            with open(os.path.join(output_dir, f"{name}.txt"), 'w', encoding='utf-8') as f:
                f.write("\n".join(sorted(data)))
        
        # Save URLs by extension
        for ext, urls in self.categorized['extensions'].items():
            # Sanitize extension for filename safety
            safe_ext = re.sub(r'[^a-z0-9]', '', ext)
            if safe_ext:  # Skip empty extensions
                with open(os.path.join(output_dir, f"{safe_ext}_urls.txt"), 'w', encoding='utf-8') as f:
                    f.write("\n".join(sorted(urls)))

def crawl_single_domain(domain, exclude, jscrawl, no_subs, scan_secrets=False):
    """Crawl a single domain and handle results"""
    crawler = WebCrawler(
        base_url=domain,
        exclude_extensions=exclude,
        jscrawl=jscrawl,
        no_subs=no_subs,
        scan_secrets=scan_secrets
    )
    
    print(f"{Fore.CYAN}{Style.BRIGHT}\n[ + ] STARTING CRAWL: {crawler.base_url}{Style.RESET_ALL}")
    if no_subs:
        print(f"{Fore.YELLOW}{Style.BRIGHT}[ ! ] SUBDOMAINS EXCLUDED FROM CRAWLING{Style.RESET_ALL}")
    if jscrawl:
        print(f"{Fore.YELLOW}{Style.BRIGHT}[ ! ] JS CRAWLING ENABLED - PRINTING URLS FOUND IN JS FILES{Style.RESET_ALL}")
    if scan_secrets:
        print(f"{Fore.YELLOW}{Style.BRIGHT}[ ! ] SECRET SCANNING ENABLED{Style.RESET_ALL}")
    
    try:
        crawler.crawl()
    except SystemExit:
        # Handle Ctrl+C graceful exit
        pass
    
    # Prompt for saving results
    save = input(f"\n{Fore.BLUE}{Style.BRIGHT}[ ? ] SAVE CATEGORIZED RESULTS? (Y/N): {Style.RESET_ALL}").strip().lower()
    if save == 'y':
        # Create directory name from domain
        parsed = urlparse(crawler.base_url)
        domain_name = parsed.netloc
        if domain_name.startswith('www.'):
            domain_name = domain_name[4:]
        domain_name = re.sub(r'[^\w\.\-]', '_', domain_name)
        output_dir = os.path.join("output", domain_name)
        crawler.save_results(output_dir)
        print(f"{Fore.GREEN}{Style.BRIGHT}[ ✓ ] RESULTS SAVED TO '{output_dir}' DIRECTORY{Style.RESET_ALL}")
