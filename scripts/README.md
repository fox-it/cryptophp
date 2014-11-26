Scripts
=======

We made the following Python scripts to help administrators to detect and identify CryptoPHP.

The scripts will require Python (preferably 2.7) to run.
We appreciate if you report bugs and/or suggestions.

check_filesystem.py
-------------------

Run this script on your server to find all "social*.png" files and determine if they are CryptoPHP backdoors. 

An optional argument can be passed to start scanning from the directory specified by the argument, else it will default to the root directory.

To scan your whole system (it can take a while), run: `./check_filesystem.py`

To scan only a specific directory, for example /var/www, run: `./check_filesystem.py /var/www`


check_url.py
------------
You can use this script to determine if your website is affected by CryptoPHP.
It does this by perfoming two HTTP requests, one and one without a webcrawler user agent.

Run the script and specify a host or url (or multiple) as the arguments, for example:

`./check_url.py --verbose www.fox-it.com http://192.168.0.10/index.php`

	Checking 'http://www.fox-it.com' ..: OK
	 * Normal request yielded 15 urls, Webcrawler request yielded 15 urls. (0 suspicous links)
	Checking 'http://192.168.0.10/index.php' ..: CRYPTOPHP DETECTED
	 * Normal request yielded 1 urls, Webcrawler request yielded 5 urls. (4 suspicous links)
	  ! http://xxxx/no-deposit-casino-bonus
	  ! http://xxxx/casino-bonus-sans-depot
	  ! http://xxxx/dolly/?p=online-casino
	  ! http://xxxx/?p=latest-casino-bonuses

If you have multiple vhosts or urls you want to check, you can make a list and run it with the `--load` flag, for example:

`./check_url.py --verbose --load=urls.txt`



