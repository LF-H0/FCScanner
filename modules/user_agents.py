# Comprehensive headers for WAF evasion

USER_AGENTS = [
    # Chrome
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36',
    
    # Firefox
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 13.5; rv:109.0) Gecko/20100101 Firefox/117.0',
    'Mozilla/5.0 (X11; Linux i686; rv:109.0) Gecko/20100101 Firefox/117.0',
    
    # Safari
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15',
    'Mozilla/5.0 (iPad; CPU OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1',
    
    # Edge
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 Edg/116.0.1938.62',
    
    # Mobile Devices
    'Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Linux; Android 13; SM-S901B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36',
    
    # Less Common Browsers
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 Vivaldi/6.1.3035.111',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 OPR/102.0.0.0',
    
    # Search Engine Crawlers
    'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)',
    
    # Legacy Browsers
    'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko',
    'Mozilla/5.0 (Windows NT 6.3; Win64; x64; Trident/7.0; rv:11.0) like Gecko',
    
    # Smart TVs
    'Mozilla/5.0 (Web0S; Linux/SmartTV) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.79 Safari/537.36 DMOST/2.0.0',
    
    # Game Consoles
    'Mozilla/5.0 (PlayStation; PlayStation 5/6.00) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.4 Safari/605.1.15'
]

REFERERS = [
    'https://www.google.com/',
    'https://www.bing.com/',
    'https://www.yahoo.com/',
    'https://www.duckduckgo.com/',
    'https://www.baidu.com/',
    'https://www.youtube.com/',
    'https://www.facebook.com/',
    'https://www.amazon.com/',
    'https://www.reddit.com/',
    'https://www.linkedin.com/',
    'https://www.twitter.com/',
    'https://www.instagram.com/',
    'https://www.pinterest.com/',
    'https://www.tumblr.com/',
    'https://www.wordpress.com/',
    'https://www.github.com/',
    'https://www.stackoverflow.com/',
    'https://www.quora.com/',
    'https://www.medium.com/',
    'https://news.ycombinator.com/',
    'https://www.wikipedia.org/',
    'https://www.nytimes.com/',
    'https://www.cnn.com/',
    'https://www.bbc.com/',
    'https://www.alexa.com/siteinfo/',
    'https://www.whois.com/',
    'https://www.archive.org/web/',
    'https://translate.google.com/',
    'https://webcache.googleusercontent.com/search?q=cache:'
]

HEADERS_TEMPLATE = {
    'Accept': '*/*',
    'Accept-Language': 'en-US,en;q=0.5',
    'DNT': '1',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'Pragma': 'no-cache',
    'TE': 'Trailers'
}

RATE_LIMIT_BYPASS_PARAMS = {
    'bypass': '1',
    'cache': '1',
    'nocache': 'RANDOM',  # Will be replaced with timestamp
    'random': 'RANDSTR'   # Will be replaced with random string
}
