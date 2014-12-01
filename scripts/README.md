Scripts
=======

We made the following Python scripts to help administrators to detect and identify CryptoPHP.

The scripts will require Python (preferably 2.7) to run.
We appreciate if you report bugs and/or suggestions.

check_filesystem.py
-------------------

	$ ./check_filesystem.py --help
	Usage: check_filesystem.py [options] directory|file [directory2|file2] [..]
	
	Options:
	  -h, --help            show this help message and exit
	  -n, --no-color        no color output [default: False]
	  -p PATTERNS, --patterns=PATTERNS
	                        scan only files matching the patterns (comma
	                        seperated) [default: *.png,*.gif,*.jpg,*.bmp]

Run this script on your server to find all image files and determine if they are CryptoPHP backdoors.

By default it will recursively scan starting from the root directory. This can be changed by passing one or multiple directories (or files) as the arguments to the script.

1. Download and make the script executable:

		$ wget https://raw.githubusercontent.com/fox-it/cryptophp/master/scripts/check_filesystem.py
		$ chmod +x check_filesystem.py

2. To scan your whole system (it can take a while), run:

		./check_filesystem.py

	Or scan a specific directory, for example `/home`:

		./check_filesystem.py /home

3. Files will either reported as suspicious or confirmed CryptoPHP shell as follows:

		File matching patterns: ['*.png', '*.gif', '*.jpg', '*.bmp']
		Recursively scanning directory: /
		 /home/www/social.png: CRYPTOPHP DETECTED! (version: 1.0)
		 /var/www/images/social.png: CRYPTOPHP DETECTED! (version: 1.0a)
		 /tmp/thumbs/admin/assets/images/thumb.png: CRYPTOPHP DETECTED! (version: 0.3x555)


The pattern for file matching can be changed using the `--patterns`. For example to scan all files you could specify:

	$ ./check_filesystem.py --patterns '*.*' /home
	File matching patterns: ['*']
	Recursively scanning directory: /home

check_url.py
------------

	$ ./check_url.py --help
	Usage: check_url.py [options] url [...]
	
	Options:
	  -h, --help            show this help message and exit
	  -l FILE, --load=FILE  load urls from file
	  --ua1=UA              normal user agent [default: nobot]
	  --ua2=UA              webcrawler user agent [default: msnbot]
	  -n, --no-color        no color output [default: False]
	  -v, --verbose         verbose output [default: False]

You can use this script to determine if your website is affected by CryptoPHP and performing the Blackhat SEO as described in our whitepaper.
It does this by perfoming two HTTP requests, one with and one without a webcrawler user agent.

This script can be run remotely and does not have to be executed on the affected server.

1. Download and make the script executable:

		$ wget https://raw.githubusercontent.com/fox-it/cryptophp/master/scripts/check_url.py
		$ chmod +x check_url.py

2. To scan a host or url (or multiple) as the arguments, run:

		./check_url.py --verbose www.fox-it.com http://192.168.0.10/index.php

		Checking 'http://www.fox-it.com' ..: OK
		 * Normal request yielded 15 urls, Webcrawler request yielded 15 urls. (0 suspicous links)
		Checking 'http://192.168.0.10/index.php' ..: CRYPTOPHP DETECTED
		 * Normal request yielded 1 urls, Webcrawler request yielded 5 urls. (4 suspicous links)
		  ! http://xxxx/no-deposit-casino-bonus
		  ! http://xxxx/casino-bonus-sans-depot
		  ! http://xxxx/dolly/?p=online-casino
		  ! http://xxxx/?p=latest-casino-bonuses

	Or scan a list of hosts or urls, run it with `--load`:

		./check_url.py --verbose --load=urls.txt



