Scripts
=======

We made the following Python scripts to help administrators to detect and identify CryptoPHP.

The scripts will require Python (preferably 2.7) to run.
We appreciate if you report bugs and/or suggestions.

check_filesystem.py
-------------------

Run this script on your server to find all "social*.png" files and determine if they are CryptoPHP backdoors. 

An optional argument can be passed to start scanning from the directory specified by the argument, else it will default to the root directory.

1. Download and make the script executable:

		$ wget https://raw.githubusercontent.com/fox-it/cryptophp/master/scripts/check_filesystem.py
		$ chmod +x check_filesystem.py

2. To scan your whole system (it can take a while), run:

		./check_filesystem.py

	Or scan a specific directory, for example `/home`:

		./check_filesystem.py /home

3. Files will either reported as suspicious or confirmed CryptoPHP shell as follows:

		Recursively scanning directory: /var/www
		/var/www/web/images/social.png: CRYPTOPHP DETECTED!
		/var/www/web/images/social1.png: POSSIBLE CRYPTOPHP!

check_url.py
------------
You can use this script to determine if your website is affected by CryptoPHP.
It does this by perfoming two HTTP requests, one and one without a webcrawler user agent.

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



