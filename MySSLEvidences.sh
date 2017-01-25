#!/bin/bash
#
# AUTHOR: Dionka
# DATE:   14 January 2017
#
# Use at your own risk
#
#
#	This tool may be used for legal purposes only. Users take full responsibility
#	for any actions performed using this tool. If these terms are not acceptable 
#	to you, then do not use this tool.
#
#	 What it does 
#	==============
#	Are you tired of days that you forgot to take evidence for poodle vulnerability? Are you loosing hours to report weak ciphers per IP?
#	This script is for you.	
#	First it runs the SSLScan tool. After that, it runs the nmap tool with several ssl scripts in order to identify ciphers, 
#	certicate details and check for several known vulnerabilities such as ccs, heartbleed, poodle.  Continiously it runs openssl
#	commands to perform a normal connection to the server, a ssl3 and a ssl2 version connection, as well as it tries any common cipher 
#	connection: RC4, DES-CBC3-SHA, EXP (for longJam). At the end, it runs three automated 
#	tools: the TestSSLServer.jar, the testssl.sh and the o-saft tool. Every command is stored  in a different txt. The main reason for this script is 
#	to be sure that any needed log exists and that most common vulnerabilities are checked.
#	Finally, it parses the files in order to organise the results for reporting reason. Just copy paste the resutls and you are done.
#	Requirements:
#	Tools: Nmap, OpenSSL that supports SSLv2 and SSLv3, Java, Perl, ack
#	3rd parties tools in use: testssl.sh, O-salt, TestSSLServer.jar
#	This tools ARE NOT MINE. I only use them to support my script
#	Input file must be in this format "ip:port" in diffrent lines

echo ""
echo -e "\e[101m                                               \e[0m"
echo -e "\e[101m        ( ) _               ( )                \e[0m"    
echo -e "\e[101m       _| |(_)   _     ___  | |/')    _ _      \e[0m"
echo -e "\e[101m     / _  || | / _ \ /  _  \| , <   / _  )     \e[0m"
echo -e "\e[101m    ( (_| || |( (_) )| ( ) || |\ \ ( (_| |     \e[0m"
echo -e "\e[101m     \__,_)(_) \___/ (_) (_)(_) (_) \__,_)     \e[0m"
echo -e "\e[101m                                               \e[0m"
echo ""


echo -e "\e[32m  [+] \e[0m\e[0m  Name the project.:                       "
read project
mkdir $project

echo -e "\e[32m  [+] \e[0m\e[0m  Name the file with the IPs on:"
read filetxt
while IFS=$' \t\n\r' read -r ips
do
	IFS=':' read -r -a array <<< "$ips"
	ip="${array[0]}"
	port="${array[1]}" 
	echo -e "\e[101m\e[1m Starting for IP:"$ip " and Port:"$port" \e[0m"
	folder=$project"/ssl_results_"$ip"_"$port
	mkdir $folder

	echo -e "\e[91m\e[1m             SSLScan                         \e[0m"
	echo -e "\e[32m  [+]  \e[0mStarting SSLScan:"
	timeout 20 sslscan  $ip:$port > $folder"/sslscan.txt"
	echo -e "\e[91m  [*] \e[0mShow the results:"
	echo -e "\e[91mroot@pentest\e[0m:\e[34m/\e[0m# sslscan "$ip":"$port
	cat $folder"/sslscan.txt"
	echo -e "\e[91m              *******                           \e[0m"

		
	echo -e "\e[91m\e[1m            NMAP Scripts                     \e[0m"
	echo -e "\e[32m  [+] \e[0mCipher enumeration:                         \e[0m"
	nmap -p $port --script ssl-enum-ciphers $ip > $folder"/ciphers.txt"
	echo -e "\e[91m  [*] \e[0mShow the results:"
	echo -e "\e[91mroot@pentest\e[0m:\e[34m/\e[0m# nmap -p "$port "--script ssl-enum-ciphers "$ip
	cat $folder"/ciphers.txt"
	echo -e "\e[91m              *******                           \e[0m"
	
	echo -e "\e[32m  [+] \e[0mCheck for CCS injection attack:             \e[0m"
	nmap -p $port --script ssl-ccs-injection $ip > $folder"/ccs.txt"
	echo -e "\e[91m  [*] \e[0mShow the results:"
	echo -e "\e[91mroot@pentest\e[0m:\e[34m/\e[0m# nmap -p "$port" --script ssl-ccs-injection "$ip	
	cat $folder"/ccs.txt"
	echo -e "\e[91m              *******                           \e[0m"
	
	echo -e "\e[32m  [+] \e[0mCheck for heartbleed attack:                \e[0m"
	nmap -p $port --script ssl-heartbleed $ip > $folder"/heartbleed.txt"
	echo -e "\e[91m  [*] \e[0mShow the results:"
	echo -e "\e[91mroot@pentest\e[0m:\e[34m/\e[0m# nnmap -p "$port" --script ssl-heartbleed" $ip 
	cat $folder"/heartbleed.txt"
	echo -e "\e[91m              *******                           \e[0m"
	echo -e "\e[91m  [*] \e[0mIf it's vulnerable to heartbleed, run the auto script in Kali!"
	echo -e "\e[91m              *******                           \e[0m"	

	echo -e "\e[32m  [+] \e[0mCheck for poodle attack with nmap:          \e[0m"
	nmap -p $port --script ssl-poodle $ip > $folder"/poodle.txt"
	echo -e "\e[91m  [*] \e[0mShow the results:"
	echo -e "\e[91mroot@pentest\e[0m:\e[34m/\e[0m# nmap -p "$port" --script ssl-poodle "$ip	
	cat $folder"/poodle.txt"
	echo -e "\e[91m              *******                           \e[0m"
	
	echo -e "\e[32m  [+] \e[0mExtracting Certificate info via nmap:       \e[0m "
	nmap -p $port --script ssl-cert $ip > $folder"/certificate2.txt"
	echo -e "\e[91m  [*] \e[0mShow the results:"
	echo -e "\e[91mroot@pentest\e[0m:\e[34m/\e[0m# nmap -p " $port" --script ssl-cert " $ip
	cat $folder"/certificate2.txt"
	echo -e "\e[91m              *******                           \e[0m"

	echo -e "\e[91m\e[1m            OpenSSL                    \e[0m"
	echo -e "\e[32m  [+] \e[0mCheck for poodle attack with openssl:       \e[0m "
	timeout 3 openssl s_client -connect $ip:$port -no_tls1 -fallback_scsv >  $folder"/poodle_openssl_fallback_notls1.txt" 
	echo -e "\e[91m  [*] \e[0mShow the results:"
	echo -e "\e[91mroot@pentest\e[0m:\e[34m/\e[0m# openssl s_client -connect "$ip":"$port" -no_tls1 -fallback_scsv"
	cat $folder"/poodle_openssl_fallback_notls1.txt"
	echo -e "\e[91m              *******                                     \e[0m"

	echo -e "\e[32m  [+] \e[0mCheck for LogJam **OPENSSL must support EXP ciphers*** \e[0m "
	timeout 3 openssl s_client -connect $ip:$port -cipher EXP > $folder/"exp.txt"
	echo -e "\e[91m  [*] \e[0mShow the results:"
	echo -e "\e[91mroot@pentest\e[0m:\e[34m/\e[0m# openssl s_client -connect "$ip":"$port" -cipher EXP"
	cat $folder"/exp.txt"
	echo -e "\e[91m              *******                           \e[0m"
	
	echo -e "\e[32m  [+] \e[0mCheck for LogJam **OPENSSL must be at least 1.0.2 version*** \e[0m "
	echo -e "\e[32m  [+] \e[0mto display the 'server temp key parameter'*** \e[0m "
	timeout 3 openssl s_client -connect $ip:$port -cipher EDH > $folder/"edh.txt"
	echo -e "\e[91m  [*] \e[0mShow the results:"
	echo -e "\e[91mroot@pentest\e[0m:\e[34m/\e[0m# openssl s_client -connect "$ip":"$port" -cipher EDH"
	cat $folder"/edh.txt"
	echo -e "\e[91m              *******                           \e[0m"
	

		
		
	

	echo -e "\e[32m  [+] \e[0mExtracting Certificate info via openssl:   \e[0m "
	timeout 3 openssl s_client -connect $ip:$port | openssl x509 -noout -text > $folder/"certificate.txt"
	echo -e "\e[91m  [*] \e[0mShow the results:"
	echo -e "\e[91mroot@pentest\e[0m:\e[34m/\e[0m# openssl s_client -connect "$ip":"$port" | openssl x509 -noout -text"
	cat $folder"/certificate.txt"
	echo -e "\e[91m              *******                           \e[0m"



	echo -e "\e[32m  [+] \e[0mCreating a normal connection via openssl    \e[0m"
	timeout 3 openssl s_client -connect $ip:$port > $folder"/simple_openssl_connection.txt"
	echo -e "\e[91m  [*] \e[0mShow the results:"
	echo -e "\e[91mroot@pentest\e[0m:\e[34m/\e[0m# openssl s_client -connect "$ip":"$port
	cat $folder"/simple_openssl_connection.txt"
	echo -e "\e[91m              *******                           \e[0m"


	echo -e "\e[32m  [+] \e[0mCreating a connection via openssl SSLv3  \e[0m "
	timeout 3 openssl s_client -connect $ip:$port -ssl3 > $folder"/openssl_connection_ssl3.txt"
	echo -e "\e[91m  [*] \e[0mShow the results:"
	echo -e "\e[91mroot@pentest\e[0m:\e[34m/\e[0m# openssl s_client -connect "$ip":"$port" -ssl3"
	cat $folder"/openssl_connection_ssl3.txt"
	echo -e "\e[91m              *******                           \e[0m"


	echo -e "\e[32m  [+] \e[0mCreating a connection via openssl SSLv2  \e[0m "
	timeout 3 openssl s_client -connect $ip:$port -ssl2 > $folder"/openssl_connection_ssl2.txt"
	echo -e "\e[91m  [*] \e[0mShow the results:"
	echo -e "\e[91mroot@pentest\e[0m:\e[34m/\e[0m# openssl s_client -connect "$ip":"$port" -ssl2"
	cat $folder"/openssl_connection_ssl2.txt"
	echo -e "\e[91m              *******                           \e[0m"


	echo -e "\e[32m  [+] \e[0mCreating a connection with RC4 cipher       \e[0m "
	timeout 3 openssl s_client -connect $ip:$port -cipher RC4 > $folder"/openssl_RC4.txt"
	echo -e "\e[91m  [*] \e[0mShow the results:"
	echo -e "\e[91mroot@pentest\e[0m:\e[34m/\e[0m# openssl s_client -connect "$ip":"$port" -cipher RC4"
	cat $folder"/openssl_RC4.txt"
	echo -e "\e[91m              *******                              \e[0m"

	echo -e "\e[32m  [+] \e[0mCreating a connection with DES-CBC3-SHA cipher \e[0m "
	timeout 3 openssl s_client -connect $ip:$port -cipher DES-CBC3-SHA > $folder"/openssl_DES_CBC3_SHA.txt"
	echo -e "\e[91m  [*] \e[0mShow the results:"
	echo -e "\e[91mroot@pentest\e[0m:\e[34m/\e[0m# openssl s_client -connect "$ip":"$port" --cipher DES-CBC3-SHA "
	cat $folder"/openssl_DES_CBC3_SHA.txt"
	echo -e "\e[91m              *******                           \e[0m"
	
	echo -e "\e[91m\e[1m         3rd parties scripts                    \e[0m"
	echo -e "\e[32m  [+] \e[0mRunning TestSSLServer.jar file...          "
	timeout 30 java -jar TestSSLServer.jar $ip $port >  $folder"/TestSSLServer_jar.txt"
	echo -e "\e[91m  [*] \e[0mShow the results:"
	echo -e "\e[91mroot@pentest\e[0m:\e[34m/\e[0m# java -jar TestSSLServer.jar "$ip" "$port
	cat $folder"/TestSSLServer_jar.txt"
	echo -e "\e[91m              *******                           \e[0m"

	echo -e "\e[32m  [+] \e[0mRunning testssl.sh file...                 "
	timeout 30 ./testssl.sh $ip:$port > $folder"/testssl_sh.txt"
	echo -e "\e[91m  [*] \e[0mShow the results:"
	echo -e "\e[91mroot@pentest\e[0m:\e[34m/\e[0m# ./testssl.sh "$ip":"$port
	cat $folder"/testssl_sh.txt"
	echo -e "\e[91m              *******                           \e[0m"

	echo -e "\e[32m  [+] \e[0mRunning o-saft.pl file..."
	timeout 30 perl O-Saft-master/o-saft.pl +check $ip:$port  >  $folder"/o-saft.txt"
	echo -e "\e[91m  [*] \e[0mShow the results:"
	echo -e "\e[91mroot@pentest\e[0m:\e[34m/\e[0m# perl O-Saft-master/o-saft.pl +check "$ip"+"$port
	cat $folder"/o-saft.txt"
	echo -e "\e[91m              *******                           \e[0m"
		
done < $filetxt

mkdir $project"/results"
cd $project
rgrep "RC4\|CBC\|'31m40'\|'31m56'\|'32m112'" | grep "Accepted\|Preferred" | grep -v SSLv3 | grep -v SSLv2 | sed "s/ssl_results_//g" | sed "s/sslscan.txt:Accepted//g" | sed "s/sslscan.txt://g" | sed "s/Preferred/ /g"  |  tr -d /  | tr _ : > "results/weak_ciphers.txt" 
#rgrep "RC4\|CBC\|40\|56\|112" | grep -v 256 | grep Accepted | grep -v SSLv3 | grep -v SSLv2 | cut -f1,3,5,6,8,9 -d" " | sed "s/ssl_results_//g" | sed "s/sslscan.txt:Accepted//g" | tr -d /  | tr _ : > "results/weak_ciphers.txt"

rgrep "SSLv2" | grep "Accepted\|Preferred" | cut -f1 -d " "  | sed "s/ssl_results_//g" | sed "s/sslscan.txt:Accepted//g" | sed "s/Preferred/ /g" | tr -d / | tr _ : | sort | uniq > "results/sslv2.txt"

rgrep "SSLv3" | grep "Accepted\|Preferred" | cut -f1 -d " "  | sed "s/ssl_results_//g" | sed "s/sslscan.txt:Accepted//g" | sed "s/Preferred/ /g" | tr -d / | tr _ : | sort | uniq > "results/sslv3.txt"

rgrep "State: VULNERABLE" | grep poodle.txt | cut -f1 -d"/" | cut -f3,4 -d"_" | tr _ :  > "results/poodle_nmap.txt"

ack -l "(check TLS_FALLBACK_SCSV mitigation below)" | ack -xl "Downgrade attack prevention NOT supported" | cut -f1 -d"/" | cut -f3,4 -d"_" | tr _ : > "results/poodle_testssl_sh.txt"

rgrep "sha1WithRSAEncryption" | grep sslscan.txt | cut -f1 -d"/" | sed "s/ssl_results_//g" | tr _ : > "results/sha1WithRSAEncryption.txt"

rgrep "RSA Key Strength" | grep sslscan | grep -v 2048  | sed 's/ssl_results_//g' | sed 's/sslscan.txt:RSA Key Strength://g' | tr -d / | tr _ : | sort | uniq > "results/cert_signed_not_2048bit.txt"

echo -e "\e[32m  [*] \e[0mThe script is now over. Everything is stored under the directory:   \e[0m"
echo -e "\e[32m  [*] \e[0m"$project


