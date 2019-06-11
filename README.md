# FreeBlacklistCheck

With the freeblacklistcheck.sh script you can quickly check whether an IP or URL has been misused by cybercriminals for malware and spam. In addition, you can query various blacklists and the ingenious API of the URLhaus project of abuse.ch - https://urlhaus.abuse.ch/api/.

## Installation:

The script also requires the JQ program to parse JSON:

    apt-get install jq

## Usage:

The easiest way is to briefly display the Help.

    ./freeblacklistcheck.sh -h

You can check individual IPs or URLs.

    ./freeblacklistcheck.sh -i <IP>
    ./freeblacklistcheck.sh -u <URL> or <DOMAIN>
    ./freeblacklistcheck.sh -i <IP> -f (Use the full blacklist - blacklist_full.txt)

## Important notes for use:

Before using this script, please read the terms of use of each blacklist provider. You can edit the entries in the input files accordingly. Entries are read from the script line by line.

    blacklist_short.txt  (Used as standard blacklist)
    blacklist_full.txt   (Used with the -f parameter)
    dnslist.txt          (Used by default for malware site check via DNS)

Thanks to the open source community for many useful ideas that have accelerated the creation of the script and to Agarzon for the blacklist script Inspiration - https://gist.github.com/agarzon/5554490! Special thanks to all blacklist operators and especially to abuse.ch for the ingenious API.

Further ideas and suggestions for improvement are very welcome.

Translated with www.DeepL.com/Translator - Thanks:-)
