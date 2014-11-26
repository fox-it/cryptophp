CryptoPHP Indicators of Compromise
==================================

This repository contains the indicators of compromise for the CryptoPHP backdoor.

The whitepaper regarding CryptoPHP can be found here:

 * http://blog.fox-it.com/2014/11/18/cryptophp-analysis-of-a-hidden-threat-inside-popular-content-management-systems/

### Available IOCs

| filename                                      | description                                                                                              |
|-----------------------------------------------|----------------------------------------------------------------------------------------------------------|
| *[file_hashes.csv](file_hashes.csv)*          | Contains the MD5 and SHA1 hashes of the different versions of the backdoor and when they were first seen |
| *[domains.txt](domains.txt)*                  | Contains the C2 domains used by the backdoor                                                             |
| *[ips.txt](ips.txt)*                          | Contains the C2 ip addresses used by the backdoor                                                        |
| *[email_addresses.txt](email_addresses.txt)*  | Contains the email addresses used as backup communication by the backdoor                                |
 

### Available scripts

We created some Python scripts to help administrators identify CryptoPHP:

[https://github.com/fox-it/cryptophp/scripts](https://github.com/fox-it/cryptophp/scripts)