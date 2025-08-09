import argparse
import sys
import time
import textwrap
from colorama import Fore, Style, init
from modules.crawler import crawl_single_domain
from modules.fuzzer import run_fuzzer

# Initialize colorama
init(autoreset=True)

def print_main_help():
    """Print main help in table format"""
    print(f"\n{Fore.CYAN}Ultimate Web Recon Tool{Style.RESET_ALL}")
    print(f"{Fore.CYAN}======================={Style.RESET_ALL}")
    print(f"\n{Fore.YELLOW}Commands:{Style.RESET_ALL}")
    print(f"{Fore.GREEN}  crawl    {Style.RESET_ALL}Website crawling")
    print(f"{Fore.GREEN}  fuzz     {Style.RESET_ALL}Web fuzzing for directories, files, or subdomains")
    print(f"\n{Fore.YELLOW}Usage:{Style.RESET_ALL}")
    print(f"  main.py [command] [options]")
    print(f"\n{Fore.YELLOW}Get command help:{Style.RESET_ALL}")
    print(f"  main.py crawl -h")
    print(f"  main.py fuzz -h")
    sys.exit(0)

def print_crawl_help():
    """Print crawl command help in table format"""
    print(f"\n{Fore.CYAN}Crawl Command{Style.RESET_ALL}")
    print(f"{Fore.CYAN}-------------{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Website crawling with JavaScript analysis{Style.RESET_ALL}\n")
    print(f"{Fore.GREEN}+------------------+-------------------------------------------------+{Style.RESET_ALL}")
    print(f"{Fore.GREEN}| Option           | Description                                     |{Style.RESET_ALL}")
    print(f"{Fore.GREEN}+------------------+-------------------------------------------------+{Style.RESET_ALL}")
    print(f"{Fore.GREEN}| -u, --url URL    | Single domain to crawl                          |{Style.RESET_ALL}")
    print(f"{Fore.GREEN}| -f, --file FILE  | File containing domains (one per line)          |{Style.RESET_ALL}")
    print(f"{Fore.GREEN}| -e, --exclude    | File extensions to exclude (e.g., jpg png pdf   |{Style.RESET_ALL}")
    print(f"{Fore.GREEN}| -j, --jscrawl    | Enable extraction of URLs from JavaScript file  |{Style.RESET_ALL}")
    print(f"{Fore.GREEN}| --no-subs        | Exclude subdomains from crawling                |{Style.RESET_ALL}")
    print(f"{Fore.GREEN}| -s, --secrets    | Scan JavaScript files for secrets               |{Style.RESET_ALL}")
    print(f"{Fore.GREEN}| -h, --help       | Show this help message                          |{Style.RESET_ALL}")
    print(f"{Fore.GREEN}+------------------+-------------------------------------------------+{Style.RESET_ALL}")
    sys.exit(0)

def print_fuzz_help():
    """Print fuzz command help in table format"""
    print(f"\n{Fore.CYAN}Fuzz Command{Style.RESET_ALL}")
    print(f"{Fore.CYAN}------------{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Web fuzzing for directories, files, or subdomains{Style.RESET_ALL}\n")
    print(f"{Fore.GREEN}+------------------+-------------------------------------------------+{Style.RESET_ALL}")
    print(f"{Fore.GREEN}| Argument/Option  | Description                                     |{Style.RESET_ALL}")
    print(f"{Fore.GREEN}+------------------+-------------------------------------------------+{Style.RESET_ALL}")
    print(f"{Fore.GREEN}| target           | Target URL or domain                            |{Style.RESET_ALL}")
    print(f"{Fore.GREEN}| -m, --mode MODE  | Fuzzing mode (dirs, files, subs)                |{Style.RESET_ALL}")
    print(f"{Fore.GREEN}| -t, --threads N  | Number of threads (default: 10)                 |{Style.RESET_ALL}")
    print(f"{Fore.GREEN}| --min-delay SEC  | Minimum delay between requests (default: 1.0s)  |{Style.RESET_ALL}")
    print(f"{Fore.GREEN}| --max-delay SEC  | Maximum delay between requests (default: 3.0s)  |{Style.RESET_ALL}")
    print(f"{Fore.GREEN}| -w, --wordlist   | Custom wordlist URL                             |{Style.RESET_ALL}")
    print(f"{Fore.GREEN}| -h, --help       | Show this help message                          |{Style.RESET_ALL}")
    print(f"{Fore.GREEN}+------------------+-------------------------------------------------+{Style.RESET_ALL}")
    sys.exit(0)

def main():
    # Set UTF-8 encoding for stdout
    sys.stdout.reconfigure(encoding='utf-8') if hasattr(sys.stdout, 'reconfigure') else None
    
    # Main parser
    parser = argparse.ArgumentParser(
        description=f"{Fore.CYAN}🚀 Ultimate Web Recon Tool{Style.RESET_ALL}",
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False
    )
    
    parser.add_argument('-h', '--help', action='store_true', help='Show this help message')
    
    subparsers = parser.add_subparsers(dest='command', help=f"{Fore.YELLOW}Available commands{Style.RESET_ALL}")
    
    # Crawler command
    crawl_parser = subparsers.add_parser(
        'crawl', 
        help='Website crawling',
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False
    )
    crawl_parser.add_argument("-u", "--url", help="Single domain to crawl")
    crawl_parser.add_argument("-f", "--file", help="File containing domains (one per line)")
    crawl_parser.add_argument("-e", "--exclude", nargs="+", default=[], 
                             help="File extensions to exclude (e.g., jpg png pdf)")
    crawl_parser.add_argument("-j", "--jscrawl", action="store_true",
                             help="Enable extraction of URLs from JavaScript files")
    crawl_parser.add_argument("--no-subs", action="store_true",
                             help="Exclude subdomains from crawling")
    crawl_parser.add_argument("-s", "--secrets", action="store_true",
                             help="Scan JavaScript files for secrets")
    crawl_parser.add_argument('-h', '--help', action='store_true', help='Show crawl help')
    
    # Fuzzer command
    fuzz_parser = subparsers.add_parser(
        'fuzz', 
        help='Web fuzzing',
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False
    )
    fuzz_parser.add_argument("target", help="Target URL or domain", nargs='?')
    fuzz_parser.add_argument("-m", "--mode", choices=["dirs", "files", "subs"], 
                             help="Fuzzing mode")
    fuzz_parser.add_argument("-t", "--threads", type=int, default=10, 
                             help="Number of threads")
    fuzz_parser.add_argument("--min-delay", type=float, default=1.0, 
                             help="Minimum delay between requests")
    fuzz_parser.add_argument("--max-delay", type=float, default=3.0, 
                             help="Maximum delay between requests")
    fuzz_parser.add_argument("-w", "--wordlist", 
                             help="Custom wordlist URL")
    fuzz_parser.add_argument('-h', '--help', action='store_true', help='Show fuzz help')
    
    # Parse arguments
    args, remaining = parser.parse_known_args()
    
    # Handle help
    if args.help and not args.command:
        print_main_help()
    
    if not args.command:
        print_main_help()
    
    # Handle command-specific help
    if args.command == 'crawl':
        if '-h' in remaining or '--help' in remaining:
            print_crawl_help()
    
    elif args.command == 'fuzz':
        if '-h' in remaining or '--help' in remaining:
            print_fuzz_help()
    
    # Re-parse with the subparser
    args = parser.parse_args()
    
    start_time = time.time()
    
    if args.command == 'crawl':
        if not args.url and not args.file:
            print(f"{Fore.RED}Error: You must provide either -u/--url or -f/--file{Style.RESET_ALL}")
            print_crawl_help()
        
        if args.file:
            with open(args.file, encoding='utf-8') as f:
                domains = [line.strip() for line in f.readlines()]
            
            for domain in domains:
                if domain:
                    crawl_single_domain(domain, args.exclude, args.jscrawl, args.no_subs, args.secrets)
        
        if args.url:
            crawl_single_domain(args.url, args.exclude, args.jscrawl, args.no_subs, args.secrets)
    
    elif args.command == 'fuzz':
        if not args.target or not args.mode:
            print(f"{Fore.RED}Error: Both target and mode are required for fuzzing{Style.RESET_ALL}")
            print_fuzz_help()
        run_fuzzer(args)
    
    print(f"\n{Fore.GREEN}Total execution time: {time.time() - start_time:.2f} seconds{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
