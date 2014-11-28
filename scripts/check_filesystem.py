#!/usr/bin/env python
#
# file:     check_filesystem.py
# author:   Fox-IT Security Research Team <srt@fox-it.com>
#
#  Scan the filesystem for the CryptoPHP backdoor.
#  It will only scan "social*.png" files.
#
#  Known MD5 hashes are compared to determine if it's really CryptoPHP.
#
#  Example usage: ./check_filesystem.py /var/www
#
import os
import sys
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
    "f30dca4a681703178b4d1294425ae5f6",
]

def is_crypto_php_shell(data):
    """ Quick check to determine if contents of file is CRYPTOPHP """
    return 'openssl_seal' in data and 'serverKey' in data

def main(directory):
    found = []
    for root, dirs, files in os.walk(directory):
        for fname in files:
            path = os.path.join(root, fname)
            if not os.path.isfile(path):
                continue

            # Only process social*.png
            fname = fname.lower()
            if not (fname.startswith('social') and fname.endswith('.png')):
                continue

            # Check contents of file
            data = ''
            f = open(path, "rb")
            data = f.read()
            f.close()

            # Not CryptoPHP, skip
            if not is_crypto_php_shell(str(data)):
                continue

            # Output warning            
            msg = 'POSSIBLE CRYPTOPHP!'
            md5_hash = md5(data).hexdigest()
            if md5_hash in CRYPTO_PHP_MD5_HASHES:
                msg = 'CRYPTOPHP DETECTED!'
            found.append(path)
            print("%s: %s" % (path, msg))

    if found:
        return 1
    return 0

if __name__ == '__main__':
    directory = "/"
    if len(sys.argv) == 2:
        directory = sys.argv[1]

    if not os.path.isdir(directory):
        print('%r is not a directory, aborting' % directory)
        sys.exit(1)

    print('Recursively scanning directory: %s' % directory)
    sys.exit(main(directory))
