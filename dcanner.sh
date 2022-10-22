#/bin/bash

#Author: Guy Shabat
#Date: 23/10/2022

#Description:
#This script gets a network range from the user or getting it automaticlly and then starts to scan the 
#network for vulnerabilities and exploits and displaying it back to the user

#Usage: dcanner.sh

echo 'welcome' | figlet
 echo
read -p "[*] choose [1] for automatic scan of your network or [2] for manually input ip range: " choice

case "$choice" in 
 1)  ipr=$(ip a | grep global | awk '{print $2}')
 
 ip=$(echo "$ipr" | cut -d "/" -f 1) #getting integers for the script
 
 if [ ! -d "$ip" ] #checks if a directory already exists if not making a new one
then
	mkdir "$ip"
		echo "[+] Directory created $ip.."
else
		echo "[!] Directory $ip already exists not created a new one..."
		rm "$ip"/EnumUsers.lst
fi

if [ ! -d scanner_etc ] #checks if a directory already exists if not making a new one
then
	mkdir scanner_etc
		echo "[+] Directory created scanner_etc"
else
		echo "[!] Directory scanner_etc already exists!"
fi	
	
	nmap "$ipr" -sL | grep for | awk '{print $NF}' > scanner_etc/ips #mapping all the network to ips	
  echo "[*] Starting to scan your network range :" $(echo "$ipr")
  echo	
  ;;
 
 2) read -p "Please enter the range of the network you would like to scan: " choice2
 
 ip=$(echo $choice2 | cut -d "/" -f 1)
 
  if [ ! -d "$ip" ]
then
	mkdir "$ip"
		echo "[+] Directory created $ip.."
else
		echo "[!] Directory $ip already exists not created a new one..."
		rm "$ip"/EnumUsers.lst
fi

if [ ! -d scanner_etc ]
then
	mkdir scanner_etc
		echo "[+] Directory created scanner_etc"
else
		echo "[!] Directory scanner_etc already exists!"
fi	
	
	nmap "$choice2" -sL | grep for | awk '{print $NF}' > scanner_etc/ips #mapping all the network to ips	
  echo "[*] Starting to scan your network range :" $(echo "$choice2")
  echo	
  ;;
  
  *) echo "Invalid option"
  esac
  
  
  if [ "$choice"=="1" ] 
  then
  echo "[*] scanning $ipr, please be patient this may take a minute or 2"
   echo
for i in $(cat scanner_etc/ips)
do
		nmap "$i" --open -F -T5 | grep open > "$ip"/$i & #scanning the network range 
done
	wait
elif [ "$choice"=="2" ] 
  then
   echo "[*] scanning $choice2, please be patient this may take a minute or 2"
  echo
    for i in $(cat scanner_etc/ips)
do
		nmap "$i" --open -F -T5 | grep open > "$ip"/$i & #scanning the network range
done
fi	
	
	ls -l "$ip" | awk '$5>0' | awk '{print $NF}' | egrep -vi [a-z] > scanner_etc/ipsopen #checking what files actually have stuff in it and writing them into a new file
	echo
	
for i in $(cat scanner_etc/ipsopen) #displaying data to the user
do 
 echo "--_--_--_--_--_--_--_--_--_--_--_--_--"
	echo "[+] Device $i open ports: "
		 cat "$ip"/"$i"
		 echo
	echo "[*] Starting scanning on open ports..."	
		nmap -F "$i" -sV -oX "$ip"/"$i"-res.xml 2>/dev/null 1>/dev/null &
	echo "--_--_--_--_--_--_--_--_--_--_--_--_--"
	echo
done
	
for i in $(cat scanner_etc/ipsopen) #checks what available services are there to brute
do
  if [ ! -z $(cat "$ip"/"$i" | awk '{print $3}' | grep 'ssh\|^ftp' | head -1) ]
  then
	echo "[!] $i have available service to brute!"
	 echo
	cat "$ip"/"$i"
	 echo
	echo "[*] Please choose service to brute: " 
	 read srvc
	 echo "You chose $srvc \033[5mStarting to brute force..\033[m"
		hydra -f -L user.lst -P password.lst "$i" "$srvc" >> scanner_etc/foundenum.lst 2>/dev/null #brute forcing the service chosen by the user
	else
	 echo
	   echo "[!] $i doesnt appear to have any availabe services to brute..."
	   echo
	fi
done		

if [ ! -z $(cat scanner_etc/foundenum.lst | grep host | head -1 | awk '{print $1}') ] #checks if the brute was succesfull or not
    then
      echo "[!] Brute force part completed sucssesfully!"
         echo
		cat scanner_etc/foundenum.lst | grep host | awk '{print $2,$3,$4,$5,$6,$7}' > "$ip"/EnumUsers.lst
	  echo "[*] You can watch list of users and password under EnumUsers.lst"
	  	 echo
	  else
	  	echo "[!] Brute force part completed but found nothing..."
	  echo	
fi	
	  	 
echo

for i in $(cat scanner_etc/ipsopen) #if to check available exploits on the ip using searchsploit engine
do
	echo "[*] Performing search for exploits on $i services"
	  searchsploit --nmap "$ip"/"$i"-res.xml > "$ip"/"$i"-searchsploit.lst 2>/dev/null
	   if [ -f "$ip"/"$i"-searchsploit.lst ]
	    then	
			echo "[!] Exploits found!"
			echo
		else
			echo " [!] Didn't found exploits"
			echo	
		fi	
done

	 echo "[+] Scanning for exploits completed all exploits saved to $ip directory"  
	  echo
	find ./"$ip"  -type f -size -1k -delete  	 
	  	 
	  #this part displays some of the data found to the user
	  
echo "[#] Total UP Devices: "$(cat scanner_etc/ipsopen | wc -l)
 echo
echo "[#] Total exploits found: " $(cat "$ip"/*-searchsploit.lst | wc -l)
 echo
echo "[#] Total weak passwords and users found: " $(cat "$ip"/EnumUsers.lst | wc -l )
