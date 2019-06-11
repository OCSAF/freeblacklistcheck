#!/bin/bash

#################################################################
################### OCSAF FreeBlacklistCheck ####################
#################################################################

######################################################################################################
#  FROM THE FREECYBERSECURITY.ORG TESTING-PROJECT (GNU-GPLv3) - https://freecybersecurity.org        #
#  With this bash script you can test if an IP or URL has been abused by cyber criminals.            #
#                                                                                                    #
#  Before using this script, please read the terms of use of each blacklist provider.                #
#  You can edit the entries in blacklist_short.txt, blacklist_full.txt and dnslist.txt accordingly.  #
#  Use only with legal authorization and at your own risk! ANY LIABILITY WILL BE REJECTED!           #
#                                                                                                    #
#  Script programming by Mathias Gut, Netchange Informatik GmbH under GNU-GPLv3                      #
#  Thanks to the community and also for your personal project support.                               #
#  Special thanks to all blacklist operators and especially to abuse.ch for the                      #
#  ingenious API https://urlhaus.abuse.ch/api/ and to Agarzon for the blacklist script               #
#  Inspiration - https://gist.github.com/agarzon/5554490                                             #
######################################################################################################


#######################
### Preparing tasks ###
#######################

#Check if JQ is installed.
program=(jq geoiplookup)
for i in "${program[@]}"; do
	if [ -z $(command -v ${i}) ]; then
		echo "${i} is not installed."
		count=1
	fi

	if [[ $count -eq 1 ]]; then
		exit
	fi
done
unset program
unset count


#######################
### TOOL USAGE TEXT ###
#######################

usage() {
	echo "From the Free OCSAF project!"
	echo "OCSAF FreeBlacklistCheck Version 1.0 - GPLv3 (https://freecybersecurity.org)"
	echo ""
	echo "*Before using this script, please read the terms of use of each blacklist provider."
        echo " You can edit the entries in blacklist_short.txt, blacklist_full.txt and dnslist.txt accordingly."
	echo " Use only with legal authorization and at your own risk!"
       	echo " ANY LIABILITY WILL BE REJECTED!*"
       	echo ""	
	echo "USAGE:" 
	echo "  ./freeblacklistcheck.sh -i <ipv4 address>"
       	echo "  ./freeblacklistcheck.sh -u <url>"	
       	echo ""	
	echo "EXAMPLE:"
       	echo "  ./freeblacklistcheck.sh -u www.freecybersecurity.org"
       	echo ""	
	echo "OPTIONS:"
	echo "  -h, help - this beautiful text"
	echo "  -i <ip> - ipv4 address for testing"
	echo "  -u <url> - url or domain to test"
	echo "  -f, full blacklist list"
	echo "  -c, no color scheme set"
       	echo ""
	echo "NOTES:"
	echo "#For more information go to - https://freecybersecurity.org"
}


##############################
### GETOPTS - TOOL OPTIONS ###
##############################

while getopts "i:u:fhc" opt; do
	case ${opt} in
		h) usage; exit 1;;
		i) ip="$OPTARG"; opt_arg1=1; opt_count=$((opt_count+1));;
		u) url="$OPTARG"; opt_arg1=1; opt_count=$((opt_count+1));;
		f) full=1;;
		c) colors=1;;
		\?) echo "**Unknown option**" >&2; echo ""; usage; exit 1;;
        	:) echo "**Missing option argument**" >&2; echo ""; usage; exit 1;;
		*) usage; exit 1;;
  	esac
  	done
	shift $(( OPTIND - 1 ))

#Check if opt_count is greater than 1	
if [[ $opt_count > 1 ]]; then
	echo "**You can only check one object at a time!**"
	echo ""
	usage; exit 1
fi

#Check if opt_arg1 is set
if [ "${opt_arg1}" == "" ]; then
	echo "**No argument set - requires ip (-i) or url (-u)**"
	echo ""
	usage
	exit 1
fi


###############
### COLORS  ###
###############

if [[ $colors -eq 1 ]]; then
	cOFF=''
	gON=''
	yON=''
	rON=''
else
	cOFF='\e[39m'	  #color OFF / Default color
	gON='\e[32m'	  #green color ON
	yON='\e[33m'	  #yellow color ON
	rON='\e[31m'	  #red color ON
fi


funcBlacklistCheck() {

	local _ip=$ip
	local _url=$url
	local _full=$full
	local _blacklist
	local _list
	local _v1
	local _v2
	local _check
	local _reversedns
	local _reverseip
	local _abuse
	local _abusestat
	local _abuseref
	local _domain
	local i
	local line

	if [ "${_full}" == "1" ]; then
		_blacklist=$(<./blacklist_full.txt)
	else
		_blacklist=$(<./blacklist_short.txt)
	fi


	if [ ! -z ${_ip} ]; then

		_reversedns=$(dig +short -x ${_ip})
		if [ -z ${_reversedns} ]; then
			_reversedns="None"
		fi

		echo -e "Tested IP: ${yON}${_ip}${cOFF}"
		echo -e "Reverse-Lookup: ${_reversedns}"
		_reverseip=$(echo ${_ip} \
			| sed -ne \
			"s~^\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)$~\4.\3.\2.\1~p")
		if [ -z ${_reverseip} ]; then
			echo -e "${yON}No valid IPv4 address!${cOFF}"
			echo ""
			exit 1
		fi
	
		_abuse=$(wget -q -O- --post-data="host=${_ip}" https://urlhaus-api.abuse.ch/v1/host/)
		_abusestat=$(echo ${_abuse} | jq '.query_status' | sed 's/\"//g')
		_abuseref=$(echo ${_abuse}| jq '.urlhaus_reference' | sed 's/\"//g')

	if [ "${_abusestat}" == "no_results" ]; then	
		printf "%-60s" " urlhaus-api.abuse.ch (${_ip})"
		echo -e "${gON}OK${cOFF}"
	else
		printf "%-60s" " urlhaus-api.abuse.ch (${_ip})"
		echo -e "${rON}listed: ${_abuseref}${cOFF}"
	fi
		
		for i in ${_blacklist}; do
    			printf "%-60s" " ${_reverseip}.${i}."
    			_list="$(dig +short -t a ${_reverseip}.${i}.)"
    			if  [ "${_list}" == "" ]; then
				echo -e "${gON}${_list:-OK}${cOFF}"
			else
				echo -e "${rON}listed: ${_list:----}${cOFF}"
			fi
		done
	fi

	if [ ! -z ${_url} ]; then
		_ip=$(host -t a ${url} | grep address | cut -d " " -f4 | head -n 1)
		
		if [ -z ${_ip} ]; then
			_ip=$(host -t a ${url} 9.9.9.10 | grep address | cut -d " " -f4 | head -n 1)
		fi

		if [ -z ${_ip} ] && [[ ${_url} == *.*.* ]]; then
			echo -e "${yON}URL could not be resolved via DNS!${cOFF}"
			echo ""
			exit 1
		elif [ -z ${_ip} ] && [[ ${_url} == *.* ]]; then
			echo -e "${yON}Domain could not be resolved via DNS!${cOFF}"
			echo ""
			exit 1
		fi
		
		_reversedns=$(dig +short -x ${_ip})
		if [ "${_reversedns}" == "" ]; then
			_reversedns="None"
		fi


		echo -e "Tested A-Record: ${yON}${_ip}${cOFF}"
		echo -e "Reverse-Lookup:" ${_reversedns}
		_reverseip=$(echo ${_ip} \
			| sed -ne \
			"s~^\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)$~\4.\3.\2.\1~p")
		if [ -z ${_reverseip} ]; then
			echo -e "${yON}No valid IPv4 address!${cOFF}"
			echo ""
			exit 1
		fi

		_abuse=$(wget -q -O- --post-data="host=${_ip}" https://urlhaus-api.abuse.ch/v1/host/)
		_abusestat=$(echo ${_abuse} | jq '.query_status' | sed 's/\"//g')
		_abuseref=$(echo ${_abuse}| jq '.urlhaus_reference' | sed 's/\"//g')
		
		if [ "${_abusestat}" == "no_results" ]; then	
			printf "%-60s" " urlhaus-api.abuse.ch (${_ip})"
			echo -e "${gON}OK${cOFF}"
		else
			printf "%-60s" " urlhaus-ai.abuse.ch (${_ip})"
			echo -e "${rON}listed: ${_abuseref}${cOFF}"
		fi
		
		for i in ${_blacklist}; do
    			printf "%-60s" " ${_reverseip}.${i}."
    			_list="$(dig +short -t a ${_reverseip}.${i}.)"
    			if  [ "${_list}" == "" ]; then
				echo -e "${gON}${_list:-OK}${cOFF}"
			else
				echo -e "${rON}listed: ${_list:----}${cOFF}"
			fi
		done
		echo ""

		unset _abuse _abusestat _abuseref
		_abuse=$(wget -q -O- --post-data="host=${_url}" https://urlhaus-api.abuse.ch/v1/host/)
		_abusestat=$(echo ${_abuse} | jq '.query_status' | sed 's/\"//g')
		_abuseref=$(echo ${_abuse}| jq '.urlhaus_reference' | sed 's/\"//g')
		
		echo -e "Tested URL: ${yON}${_url}${cOFF}"

		if [ "${_abusestat}" == "no_results" ]; then
			_domain=$(echo ${url} | sed -r 's/.*\.([^.]+\.[^.]+)$/\1/')	
			
			unset _abuse _abusestat _abuseref
			_abuse=$(wget -q -O- --post-data="host=${_domain}" https://urlhaus-api.abuse.ch/v1/host/)
			_abusestat=$(echo ${_abuse} | jq '.query_status' | sed 's/\"//g')
			_abuseref=$(echo ${_abuse}| jq '.urlhaus_reference' | sed 's/\"//g')
			
			if [ "${_abusestat}" == "no_results" ]; then
				printf "%-60s" " urlhaus-api.abuse.ch (${_url})"
				echo -e "${gON}OK${cOFF}"
			else
				printf "%-60s" " urlhaus-api.abuse.ch (${_domain})"
				echo -e "${rON}listed: ${_abuseref}${cOFF}"
			fi
		else
			printf "%-60s" " urlhaus-api.abuse.ch (${_url})"
			echo -e "${rON}listed: ${_abuseref}${cOFF}"
		fi
			
		while read line
		do
			_v1=$(echo "${line}" | awk -F ';;' '{print $1}')
			_v2=$(echo "${line}" | awk -F ';;' '{print $2}')

			_check=$(dig ${_url} @${_v1} +recurse +short)
			printf "%-60s" " ${_v2} (${_v1})"
			if [ "${_check}" != "" ]; then
				echo -e "${gON}OK${cOFF}"
			else
				echo -e "${rON}listed${cOFF}"
			fi
		
			unset _check
			unset _v1
			unset _v2

		done <./dnslist.txt
	fi
}


############
### MAIN ###
############

echo ""
echo "##########################################"
echo "####  OCSAF FreeBlacklistCheck GPLv3  ####"
echo "####  https://freecybersecurity.org   ####"
echo "##########################################"
echo ""

if [ "$opt_arg1" == "1" ]; then             #Query only one value
	funcBlacklistCheck
	unset domain ip url full opt_arg1
	echo ""
fi

################### END ###################
