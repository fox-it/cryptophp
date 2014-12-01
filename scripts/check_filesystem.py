#!/usr/bin/env python
#
# file:     check_filesystem.py
# author:   Fox-IT Security Research Team <srt@fox-it.com>
#
#  Scan the filesystem for the CryptoPHP backdoor.
#  It will only scan files matching the given file patterns.
#  By default this is: *.png, *.gif, *.bmp, *.jpg
#
#  Known MD5 hashes are compared to determine if it's really CryptoPHP.
#
#  Example usage: ./check_filesystem.py /var/www
#
import re
import os
import sys
import fnmatch
import optparse
try:
    from hashlib import md5
except ImportError:
    from md5 import md5

# from https://github.com/fox-it/cryptophp/blob/master/file_hashes.csv
CRYPTO_PHP_MD5_HASHES = [
    "048a54b0f740991a763c040f7dd67d2b", "d3c9f64b8d1675f02aa833d83a5c6342",
    "3a2ca46ec07240b78097acc2965b352e", "4c641297fe142aea3fd1117cf80c2c8b",
    "e27122ba785627fca79b4a19c8eea38b", "2640b3613223dbb3606d59aa8fc0465f",
    "f5d6f783d39336ee30e17e1bc7f8c2ef", "b75c82e68870115b45f6892bd23e72cf",
    "29576640791ac19308d3cd36fb3ba17b", "b4764159901cbb6da443e789b775b928",
    "1ed6cc30f83ac867114f911892a01a2d", "325fc9442ae66d6ad8e5e71bb1129894",
    "5b1d09f70dcfe7a3d687aaef136c18a1", "20671fafa76b2d2f4ba0d2690e3e07dc",
    "3249b669bb11f49a76850660411720e2", "ffd91f505d56189819352093268216ad",
    "b4b2c193f8af66b093ce1f1d284406a5", "d11e6a54fba32fee9c69aabe9515e69d",
    "f30dca4a681703178b4d1294425ae5f6", "9e73a60d350a213f70231d0a37e1df2f",
]

FNMATCH_PATTERNS = ["*.png", "*.gif", "*.jpg", "*.bmp"]
REGEX_VERSION = re.compile(".*'ver'[^=]*=\s*([^;]*);.*", re.MULTILINE)

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


def is_crypto_php_shell(data):
    """ Quick check to determine if contents of file is CRYPTOPHP """
    return 'openssl_seal' in data and 'serverKey' in data

def cryptophp_version(buf):
    for line in buf.splitlines():
        match = REGEX_VERSION.match(line)
        if match:
            return match.group(1).strip('"').strip("'")
    return None

def scan_file(path):
    """ Scan a file for CryptoPHP.
    Returns (path, msg) if file is CryptoPHP, otherwise None
    """
    data = ''
    f = open(path, "rb")
    data = f.read()
    f.close()

    # Not CryptoPHP, skip
    if not is_crypto_php_shell(data.decode("utf-8", "replace")):
        return None

    # Determine version
    version = cryptophp_version(data.decode("utf-8", "replace"))

    # return result
    msg = bold(yellow('POSSIBLE CRYPTOPHP!'))
    md5_hash = md5(data).hexdigest()
    if md5_hash in CRYPTO_PHP_MD5_HASHES:
        msg = bold(red('CRYPTOPHP DETECTED!'))

    if version:
        msg += ' (version: %s)' % bold(version)

    return (bold(path), msg)

def scan_directory(directory, patterns):
    """ Recursively scan the `directory` for CryptoPHP.
    It will only scan files that match `patterns`.

    yields (path, msg) for scan results
    """
    for root, dirs, files in os.walk(directory):
        for fname in files:
            path = os.path.join(root, fname)
            if not os.path.isfile(path):
                continue

            # Only process files matching `patterns`
            to_process = False
            for pattern in patterns:
                # case insensitive match
                if fnmatch.fnmatch(fname.lower(), pattern):
                    to_process = True
                    break
            if not to_process:
                continue

            # Check contents of file
            result = scan_file(path)
            if result:
                yield result

def main():
    parser = optparse.OptionParser(usage="usage: %prog [options] directory|file [directory2|file2] [..]")
    parser.add_option("-n", "--no-color", dest="nocolor", action="store_true",
            default=False,
            help="no color output [default: %default]")
    parser.add_option("-p", "--patterns", dest="patterns", action="store",
            default=",".join(FNMATCH_PATTERNS),
            help="scan only files matching the patterns (comma seperated) [default: %default]")

    (options, args) = parser.parse_args()

    if options.nocolor:
        global bold, cyan, green, red, yellow
        bold = cyan = green = red = yellow = nocolor

    options.patterns = options.patterns.split(",")
    print("File matching patterns: %r" % options.patterns)

    # default to root if user did not specify a directory as argument
    if not args:
        args = ["/"]

    found = []
    for directory in args:
        if not os.path.exists(directory):
            print('File or directory does not exist: %s, skipping' % directory)
            continue
        if os.path.isfile(directory):
            print('Scanning file: %s' % directory)
            result = scan_file(directory)
            if result:
                print(" %s: %s" % result)
                found.append(result)
            continue
        print('Recursively scanning directory: %s' % directory)
        for result in scan_directory(directory, options.patterns):
            print(" %s: %s" % result)
            found.append(result)

    if found:
        return 1
    return 0

if __name__ == '__main__':
    sys.exit(main())
