import requests
import concurrent.futures
from urllib.parse import urlparse, urljoin, urlunparse
import sys
import time
import signal
from colorama import Fore, Style, init
import random
import hashlib
import re
import socket
import queue
import threading
import os
import json
import shutil
from .wordlists import WORDLIST_REPOS
from .user_agents import USER_AGENTS, REFERERS, HEADERS_TEMPLATE

# Initialize colorama
init(autoreset=True)

class WebFuzzer:
    def __init__(self, target, threads=10, timeout=10, min_delay=1.0, max_delay=3.0):
        # Normalize target URL
        self.target = self.normalize_target(target)
        self.threads = threads
        self.timeout = timeout
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.session = requests.Session()
        self.running = True
        self.mode = ""
        self.session_rotation_count = 0
        self.request_count = 0
        self.last_request_time = time.time()
        self.progress_counter = 0
        self.progress_total = 0
        self.progress_lock = threading.Lock()
        self.found_counter = 0
        self.baseline = self.get_baseline_response()
        self.wildcard_detected = False
        self.wildcard_baseline = None
        self.dns_cache = {}
        self.stdout_lock = threading.Lock()
        self.last_progress_update = 0
        self.subdomain_threads = 100  # Special high thread count for subdomains

        # Handle Ctrl+C
        signal.signal(signal.SIGINT, self.signal_handler)

    def normalize_target(self, target):
        """Normalize target URL to handle different formats"""
        if not target.startswith(('http://', 'https://')):
            # Try both schemes
            try:
                response = requests.head(
                    f"https://{target}",
                    headers=self.get_random_headers(),
                    timeout=3,
                    allow_redirects=False
                )
                if response.status_code < 400:
                    return f"https://{target.rstrip('/')}/"
            except:
                pass
            
            return f"http://{target.rstrip('/')}/"
        
        # Ensure URL ends with a slash
        if not target.endswith('/'):
            target += '/'
        return target

    def get_baseline_response(self):
        """Get baseline response for false positive detection"""
        baseline_url = urljoin(self.target, f"non-existent-{random.randint(10000,99999)}")
        try:
            response = self.session.head(
                baseline_url,
                headers=self.get_random_headers(),
                timeout=self.timeout,
                allow_redirects=False
            )
            return {
                'status': response.status_code,
                'length': response.headers.get('Content-Length', '0'),
                'headers': dict(response.headers),
                'hash': hashlib.md5(response.content).hexdigest()[:8]
            }
        except:
            return None

    def detect_wildcard(self):
        """Detect wildcard DNS configuration"""
        random_sub = f"wildcard-test-{random.randint(10000,99999)}"
        domain = urlparse(self.target).netloc
        if ':' in domain:
            domain = domain.split(':')[0]
        if domain.startswith('www.'):
            domain = domain[4:]

        try:
            socket.getaddrinfo(f"{random_sub}.{domain}", None)
            url = f"{urlparse(self.target).scheme}://{random_sub}.{domain}/"
            response = self.safe_request('HEAD', url)
            if response:
                self.wildcard_baseline = {
                    'status': response.status_code,
                    'length': response.headers.get('Content-Length', '0'),
                    'headers': dict(response.headers),
                    'hash': hashlib.md5(response.content).hexdigest()[:8]
                }
                self.wildcard_detected = True
        except:
            pass

    def get_random_headers(self):
        """Generate random headers to avoid WAF detection"""
        headers = HEADERS_TEMPLATE.copy()
        headers['User-Agent'] = random.choice(USER_AGENTS)
        headers['Referer'] = random.choice(REFERERS)
        headers['X-Forwarded-For'] = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        headers['Accept-Encoding'] = random.choice(['gzip', 'deflate', 'br'])
        headers['Accept-Language'] = random.choice(['en-US,en;q=0.9', 'fr-FR,fr;q=0.8', 'de-DE,de;q=0.7'])
        return headers

    def get_jittered_delay(self):
        """Get jittered delay based on current settings"""
        base_delay = random.uniform(self.min_delay, self.max_delay)
        jitter = random.uniform(-0.5, 0.5)
        return max(0.1, base_delay + jitter)  # Ensure minimum 0.1s delay

    def safe_request(self, method, url):
        """Make requests with WAF bypass and retry logic"""
        # Add jittered delay
        delay = self.get_jittered_delay()
        elapsed = time.time() - self.last_request_time
        if elapsed < delay:
            time.sleep(delay - elapsed)

        self.last_request_time = time.time()
        self.request_count += 1

        try:
            response = self.session.request(
                method,
                url,
                headers=self.get_random_headers(),
                timeout=self.timeout,
                allow_redirects=False
            )

            # Rotate session periodically
            self.session_rotation_count += 1
            if self.session_rotation_count % 50 == 0:
                self.session = requests.Session()

            return response
        except (requests.ConnectionError, requests.Timeout, requests.RequestException):
            return None

    def signal_handler(self, signum, frame):
        """Handle Ctrl+C interrupt"""
        self.running = False
        with self.stdout_lock:
            print(f"\n{Fore.YELLOW}{Style.BRIGHT}Fuzzing interrupted by user{Style.RESET_ALL}")
        sys.exit(0)

    def fetch_wordlist(self, wordlist_url):
        """Fetch wordlist from GitHub"""
        try:
            response = requests.get(
                wordlist_url,
                headers=self.get_random_headers(),
                timeout=self.timeout
            )
            if response.status_code == 200:
                return [line.strip() for line in response.text.splitlines() if line.strip()]
            return []
        except Exception:
            return []

    def print_result(self, path, status_code, content_length):
        """Print results with mode-specific formatting"""
        # Create result line based on mode
        if self.mode == "dirs":
            tag = f"{Fore.CYAN}{Style.BRIGHT}[PATH]{Style.RESET_ALL}"
            result_line = f"{tag} {path} {Fore.WHITE}| {Fore.GREEN}{status_code}{Fore.WHITE} | {Fore.CYAN}{content_length}{Style.RESET_ALL}"
        elif self.mode == "files":
            tag = f"{Fore.GREEN}{Style.BRIGHT}[FILE]{Style.RESET_ALL}"
            result_line = f"{tag} {path} {Fore.WHITE}| {Fore.GREEN}{status_code}{Fore.WHITE} | {Fore.CYAN}{content_length}{Style.RESET_ALL}"
        elif self.mode == "subs":
            tag = f"{Fore.YELLOW}{Style.BRIGHT}[SUB]{Style.RESET_ALL}"
            result_line = f"{tag} {path} {Fore.WHITE}| {Fore.GREEN}{status_code}{Fore.WHITE} | {Fore.CYAN}{content_length}{Style.RESET_ALL}"

        # Print the result immediately
        with self.stdout_lock:
            print(result_line)

        with self.progress_lock:
            self.found_counter += 1

    def is_false_positive(self, response):
        """Enhanced false positive detection with content validation"""
        if not self.baseline:
            return False

        # Skip if content length is 0
        content_length = response.headers.get('Content-Length', '0')
        if content_length == '0' or content_length == 0:
            return True

        # Compare with baseline
        baseline_status = self.baseline['status']
        baseline_length = self.baseline['length']
        baseline_hash = self.baseline['hash']

        response_hash = hashlib.md5(response.content).hexdigest()[:8]

        # Check for matching patterns
        if (response.status_code == baseline_status and
            content_length == baseline_length and
            response_hash == baseline_hash):
            return True

        # Check headers similarity
        baseline_headers = set(self.baseline['headers'].items())
        response_headers = set(response.headers.items())
        if len(baseline_headers - response_headers) < 3:  # Allow minor differences
            return True

        return False

    def is_wildcard_match(self, response):
        """Check if subdomain response matches wildcard baseline"""
        if not self.wildcard_baseline or not self.wildcard_detected:
            return False

        content_length = response.headers.get('Content-Length', '0')
        response_hash = hashlib.md5(response.content).hexdigest()[:8]

        return (response.status_code == self.wildcard_baseline['status'] and
                content_length == self.wildcard_baseline['length'] and
                response_hash == self.wildcard_baseline['hash'])

    def fuzz_directory(self, path):
        """Fuzz directories with strict validation"""
        if not self.running:
            return

        # Construct URL
        url = urljoin(self.target, path)

        try:
            response = self.safe_request('HEAD', url)
            if not response:
                return

            content_length = response.headers.get('Content-Length', '0')

            # Skip 404 and false positives
            if response.status_code == 404 or self.is_false_positive(response):
                return

            # Print result
            self.print_result(url, response.status_code, content_length)

        except Exception:
            pass

    def fuzz_file(self, file):
        """Fuzz files with strict validation"""
        if not self.running:
            return

        base_url = self.target.rstrip('/')
        extensions = ['', '.php', '.html', '.js', '.bak', '.txt', '.json', '.xml', '.conf', '.yaml', '.env']

        for ext in extensions:
            url = f"{base_url}/{file}{ext}"
            try:
                response = self.safe_request('HEAD', url)
                if not response:
                    continue

                content_length = response.headers.get('Content-Length', '0')

                # Skip 404 and false positives
                if response.status_code == 404 or self.is_false_positive(response):
                    continue

                self.print_result(url, response.status_code, content_length)

            except Exception:
                pass

    def resolve_dns(self, subdomain):
        """Resolve DNS with caching and timeout"""
        if subdomain in self.dns_cache:
            return self.dns_cache[subdomain]

        try:
            # Set DNS timeout to 1 second
            socket.setdefaulttimeout(1.0)
            socket.getaddrinfo(subdomain, None)
            self.dns_cache[subdomain] = True
            return True
        except (socket.gaierror, socket.timeout):
            self.dns_cache[subdomain] = False
            return False

    def fuzz_subdomain(self, subdomain):
        """Optimized subdomain fuzzing with DNS-first approach"""
        if not self.running:
            return

        parsed = urlparse(self.target)
        domain = parsed.netloc

        # Handle ports in domain
        if ':' in domain:
            domain = domain.split(':')[0]

        # Handle www. prefix
        if domain.startswith('www.'):
            domain = domain[4:]

        target_domain = f"{subdomain}.{domain}"
        url = f"{parsed.scheme}://{target_domain}/"

        # DNS resolution with caching
        dns_resolved = self.resolve_dns(target_domain)
        if not dns_resolved:
            return

        # Make HTTP request
        try:
            response = self.safe_request('HEAD', url)
            if not response:
                return

            content_length = response.headers.get('Content-Length', '0')

            # Skip wildcard matches
            if self.is_wildcard_match(response):
                return

            # Only show 200 OK in subs mode
            if response.status_code == 200:
                self.print_result(url, response.status_code, content_length)
        except Exception:
            pass

    def worker(self, q, wordlist_name):
        """Worker thread for processing fuzzing tasks"""
        while self.running and not q.empty():
            try:
                word = q.get_nowait()
                if self.mode == "dirs":
                    self.fuzz_directory(word)
                elif self.mode == "files":
                    self.fuzz_file(word)
                elif self.mode == "subs":
                    self.fuzz_subdomain(word)

                with self.progress_lock:
                    self.progress_counter += 1

                q.task_done()
            except queue.Empty:
                break

    def run_wordlist(self, wordlist_url, wordlist_name):
        """Run fuzzing for a specific wordlist"""
        if not self.running:
            return False

        # Print progress info with bold styling
        with self.stdout_lock:
            print(f"\n{Fore.LIGHTBLACK_EX}{Style.BRIGHT}[ - ] STARTING WORDLIST: {wordlist_name}{Style.RESET_ALL}")
            print(f"{Fore.LIGHTBLACK_EX}{Style.BRIGHT}[ - ] SOURCE: {wordlist_url}{Style.RESET_ALL}")
            print(f"{Fore.LIGHTBLACK_EX}{Style.BRIGHT}----------------------------------------------------------------{Style.RESET_ALL}")

        wordlist = self.fetch_wordlist(wordlist_url)
        if not wordlist:
            with self.stdout_lock:
                print(f"{Fore.RED}{Style.BRIGHT}Failed to fetch wordlist: {wordlist_url}{Style.RESET_ALL}")
            return False

        # Pre-filter wordlist
        if self.mode == "dirs":
            wordlist = [w for w in wordlist if w and not w.startswith(('#', '//'))]
        elif self.mode == "files":
            wordlist = [w for w in wordlist if w and '.' in w]
        elif self.mode == "subs":
            wordlist = [w for w in wordlist if w and w.replace('.', '').isalnum()]

        # Set progress counters
        with self.progress_lock:
            self.progress_counter = 0
            self.progress_total = len(wordlist)
            self.found_counter = 0

        # Create queue and add words
        q = queue.Queue()
        for word in wordlist:
            q.put(word)

        # Determine thread count based on mode
        thread_count = self.subdomain_threads if self.mode == "subs" else self.threads

        # Start worker threads
        threads = []
        for _ in range(min(thread_count, len(wordlist))):
            t = threading.Thread(target=self.worker, args=(q, wordlist_name))
            t.daemon = True
            t.start()
            threads.append(t)

        # Wait for queue to be processed
        try:
            while not q.empty() and self.running:
                time.sleep(0.5)
        except KeyboardInterrupt:
            self.running = False

        # Wait for all threads to complete
        q.join()

        # Print progress summary
        with self.stdout_lock:
            print(f"\n{Fore.LIGHTBLACK_EX}{Style.BRIGHT}[ - ] PROGRESS : {self.progress_counter}/{self.progress_total} | FOUND: {self.found_counter}{Style.RESET_ALL}")

        # Print completion message
        mode_name = self.mode.upper()
        if mode_name == "SUBS":
            mode_name = "SUBDOMAINS"

        with self.stdout_lock:
            print(f"{Fore.YELLOW}{Style.BRIGHT}[ ! ] SCAN COMPLETED{Style.RESET_ALL}")
            print(f"{Fore.GREEN}{Style.BRIGHT}[+] TOTAL {mode_name} FOUND: {self.found_counter}{Style.RESET_ALL}")

        return True

    def select_wordlist(self, available_wordlists):
        """Prompt user to select a wordlist from available options"""
        print(f"\n{Fore.YELLOW}{Style.BRIGHT}Available wordlists for {self.mode} mode:{Style.RESET_ALL}")
        for i, (name, url) in enumerate(available_wordlists, 1):
            print(f"{i}. {name}")
        
        while True:
            try:
                choice = input(f"\n{Fore.BLUE}{Style.BRIGHT}Enter the number of the wordlist to use: {Style.RESET_ALL}")
                if choice.isdigit():
                    index = int(choice) - 1
                    if 0 <= index < len(available_wordlists):
                        return available_wordlists[index]
                print(f"{Fore.RED}Invalid selection. Please enter a number between 1 and {len(available_wordlists)}")
            except KeyboardInterrupt:
                print(f"{Fore.RED}Operation cancelled by user")
                sys.exit(1)

    def run(self, mode, custom_wordlist=None):
        """Run fuzzing with wordlist progression"""
        self.mode = mode

        # Special setup for subdomain mode
        if self.mode == "subs":
            self.detect_wildcard()
            if self.wildcard_detected:
                with self.stdout_lock:
                    print(f"{Fore.YELLOW}{Style.BRIGHT}[ ! ] Wildcard DNS detected. Filtering wildcard responses...{Style.RESET_ALL}")

        if custom_wordlist:
            self.run_wordlist(custom_wordlist, "custom")
        else:
            available_wordlists = WORDLIST_REPOS[mode]
            selected_wordlist = self.select_wordlist(available_wordlists)
            self.run_wordlist(selected_wordlist[1], selected_wordlist[0])

def run_fuzzer(args):
    """Run fuzzer from main entry point"""
    fuzzer = WebFuzzer(
        args.target,
        threads=args.threads,
        min_delay=args.min_delay,
        max_delay=args.max_delay
    )
    fuzzer.run(args.mode, args.wordlist)
