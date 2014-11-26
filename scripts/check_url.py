#!/usr/bin/env python
#
# file:     check_url.py
# author:   Fox-IT Security Research Team <srt@fox-it.com>
#
#  Scan urls/hosts to determine if the site is affected by CryptoPHP.
#  It performs two HTTP requests: with and without a webcrawler user agent.
#
#  The amount of links that are returned by both requests are compared.
#  When the amount of links with a webcrawler user agent is more than
#  the normal request, it will flag it as a possible CryptoPHP.
#
#  If extra (suspicious) links are found that are related to gambling, it
#  will flag it as CryptoPHP.
#
#  Use the --verbose flag to see more output of the command.
#
#  Example usage: ./check_url.py -v [website1] [website2]
#
import re
import sys
import optparse

try:
    from urllib.request import urlopen, Request
    from urllib.error import HTTPError
except ImportError:
    from urllib2 import urlopen, Request, HTTPError

SUSPICIOUS_WORDS = ("poker", "casino", "money", "blackjack", "slot-machines", "roulette")
REGEX_URLS = re.compile(r'(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:\'".,<>?\xab\xbb\u201c\u201d\u2018\u2019]))')

UA_NORMAL = "nobot"
UA_BOT = "msnbot"

KBOLD = '\033[1m'
KRED = '\x1B[31m'
KCYAN = '\x1B[36m'
KGREEN = '\x1B[32m'
KYELLOW = '\x1B[33m'
KNORM = '\033[0m'

def bold(text):
    return KBOLD + text + KNORM

def cyan(text):
    return KCYAN + text + KNORM

def green(text):
    return KGREEN + text + KNORM

def red(text):
    return KRED + text + KNORM

def yellow(text):
    return KYELLOW + text + KNORM

def nocolor(text):
    return text

def get_page_urls(url, user_agent=None):
    req = Request(url)
    if user_agent:
        req.add_header('User-Agent', user_agent)
    response = urlopen(req)
    urls = REGEX_URLS.findall(str(response.read()))
    return set(url[0] for url in urls)

def main():
    parser = optparse.OptionParser(usage="usage: %prog [options] url [...]")
    parser.add_option("-l", "--load", dest="load", action="store", 
            default=None, metavar='FILE',
            help="load urls from file")
    parser.add_option("--ua1", dest="ua1", action="store", 
            default=UA_NORMAL, metavar='UA',
            help="normal user agent [default: %default]")
    parser.add_option("--ua2", dest="ua2", action="store", 
            default=UA_BOT, metavar='UA',
            help="webcrawler user agent [default: %default]")
    parser.add_option("-n", "--no-color", dest="nocolor", action="store_true",
            default=False,
            help="no color output [default: %default]")
    parser.add_option("-v", "--verbose", dest="verbose", action="store_true",
            default=False,
            help="verbose output [default: %default]")

    (options, args) = parser.parse_args()

    if not args and options.load is None:
        parser.print_help()
        return 1

    if options.nocolor:
        global bold, cyan, green, red, yellow
        bold = cyan = green = red = yellow = nocolor

    if options.load:
        args = open(options.load, "r")

    for host in args:
        url = host.strip()
        if not url.startswith('http'):
            url = 'http://' + url
        msg = "Checking {0!r} ".format(url)
        sys.stdout.write(bold(msg))
        sys.stdout.flush()
        a = b = None
        try:
            a = get_page_urls(url, options.ua1)
            if options.verbose:
                sys.stdout.write(".")
                sys.stdout.flush()
            b = get_page_urls(url, options.ua2)
            if options.verbose:
                sys.stdout.write(".")
                sys.stdout.flush()
        except HTTPError as e:
            sys.stdout.write(": ")
            sys.stdout.write(yellow("UNKNOWN") + " ({0})\n".format(e))
            continue

        difference = b ^ a
        suspicious_links = set()
        for url in difference:
            for word in SUSPICIOUS_WORDS:
                if word in url.lower():
                    suspicious_links.add(url)
        
        sys.stdout.write(": ")
        if suspicious_links:
            msg = red("CRYPTOPHP DETECTED")
        elif difference:
            msg = yellow("POSSIBLE CRYPTOPHP DETECTED")
        else:
            msg = green("OK")
        sys.stdout.write(bold("{0}\n".format(msg)))

        if options.verbose:
            sys.stdout.write(" * Normal request yielded {0} urls, Webcrawler request yielded {1} urls. ({2} suspicous links)\n".format(
                len(a), len(b), len(suspicious_links),
            ))
            for url in difference:
                if url in suspicious_links:
                    sys.stdout.write(red("  ! {0}\n".format(url)))
                else:
                    sys.stdout.write("  - {0}\n".format(url))

if __name__ == '__main__':
    sys.exit(main())

