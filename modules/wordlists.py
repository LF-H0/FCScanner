# Directory wordlists (small to large)
DIR_WORDLISTS = [
    ("quick", "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/quickhits.txt"),
    ("common", "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"),
    ("directory-list-2.3-small", "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-small.txt"),
    ("raft-small", "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-directories.txt"),
    ("directory-list-2.3-medium", "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt"),
    ("raft-medium", "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt"),
    ("big", "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/big.txt"),
    ("directory-list-2.3-big", "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-big.txt"),
    ("raft-large", "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt"),
]

# File wordlists (small to large)
FILE_WORDLISTS = [
    ("quick", "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/quickhits.txt"),
    ("common", "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Common-Filenames.txt"),
    ("raft-small-files", "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-files.txt"),
    ("js", "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/javascript.fuzz.txt"),
    ("configs", "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Common-DB-Backups.txt"),
    ("raft-medium-files", "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-files.txt"),
    ("raft-large-files", "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-files.txt"),
    ("all-extensions", "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-extensions.txt"),
]

# Subdomain wordlists
SUB_WORDLISTS = [
    ("subdomains-top1million-110000", "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt"),
    ("jhaddix-gist", "https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw"),
    ("deepmagic-top500", "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/deepmagic.com-prefixes-top500.txt")
]

# Organized by mode
WORDLIST_REPOS = {
    "dirs": DIR_WORDLISTS,
    "files": FILE_WORDLISTS,
    "subs": SUB_WORDLISTS,
}
