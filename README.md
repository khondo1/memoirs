# Somewhere for stuff
# To sort:
Tools needed:
`ruby -v`
`python --version`
`php -v`
`java -v`

- Homebrew 
*Homebrew installs the stuff you need that Apple did not* 
`/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"`
- jq 
`brew install jq` 
- curl 
`brew install curl` 
- wget 
`brew install wget` 
- wireshark 
`brew install wireshark` 
- nmap 
`brew install nmap` 
- proxychains 
`brew install proxychains-ng` 
- watch 
`brew install watch` 
- pip 
*pip is a package management system used to install and manage software packages written in Python* 
`sudo easy_install pip` 
- Git 
`git --version` 

```
| jq .
| python -m json.tool
eg:
echo '{"foo": 0}' | jq .
{
    "foo": 0
}
```
```
bash -x
ls | xargs -0
for i in 192.168.0.1 192.168.1.1 192.168.2.1; do host $i; done
python -c "print('hello bob')"
ls | fold -w17
ls | tee
atime aka ls -l
mtime aka ls -lu
ctime aka ls -lc
stat -x
egrep -i "select|union|waitfor|from" attack.log
curl -A "UserAgentStringHerePleaseThanks" -u admin:admin
curl --header "X-MyHeader: 123" www.google.com
curl -s 
curl --proxy yourproxy:port http://yoururl.com
curl --sslv2 https://yoururl.com
curl --insecure https://yoururl.com
curl -i -H "Accept: application/json" -H "Content-Type: application/json" http://hostname/resource
-JSON
curl -H "Accept: application/xml" -H "Content-Type: application/xml" -X GET http://hostname/resource
-XML
curl --data "param1=value1&param2=value2" http://hostname/resource
-POST DATA
curl --form "fileupload=@filename.txt" http://hostname/resource
-FILE UPLOAD
alias ll='ls -halp'
egrep '^[^#]+'
egrep '^[^#]+' /usr/local/etc/proxychains.conf
which nmap
find /usr/local/ -name nmap
find . -fstype local -mmin -10000 (minutes)

sqlmap -u 192.168.0.1
nslookup -query=any google.com
host parliament.uk - forwardDNS
host 34.250.170.198 - rDNS
curl icanhazip.com
curl ifconfig.co
dig +short myip.opendns.com @resolver1.opendns.com
ps -ef |grep sen
expr 42 - 25
ipcalc 192.168.0.1/24

/usr/bin/nc -l 1234
/usr/bin/nc 127.0.0.1 1234
/usr/bin/nc -l 1234 > filename.out

nmap --script ssl-enum-ciphers -p 443 www.example.com
- supported ciphers
openssl s_client -connect url:443
- cert and ciphers
echo | openssl s_client -servername <url> -connect <url>:443 2>/dev/null | openssl x509 -noout -issuer -subject -dates
- cert data

openssl rand -base64 12
- gen a rand pass
echo QWxhZGRpbjpvcGVuIHNlc2FtZQ== | base64 --decode
- decode base64
echo | openssl s_client -servername shellhacks.com -connect shellhacks.com:443 2>/dev/null | openssl x509
- get certificate (encoded)
echo | openssl s_client -servername www.shellhacks.com -connect www.shellhacks.com:443 2>/dev/null | openssl x509 -noout -text
- get certificate (decoded)
strings a.out
stat -x a.out 
strings -n 10 <file>
- specify the minimum string length
kextstat | grep crow
ps -ax |grep -i sen
pkgutil --pkgs |grep sen


//wireshark && tshark filters
kerberos.cname
kerberos.CNameString
ntlmssp.auth.username
ip contains dropbox
krb5
http contains GET
tcp.port eq 25 or icmp
ip.src==192.168.0.0/16 and ip.dst==192.168.0.0/16
http.user_agent contains Java
http contains 401
ssl.handshake.certificate
tcp portrange 1501-1549
3 way handshake:
tcp.flags.syn==1 or (tcp.seq==1 and tcp.ack==1 and tcp.len==0 and tcp.analysis.initial_rtt)
SYN flood:
tcp.flags.syn == 1 and tcp.flags.ack == 0

tshark -r traffic-analysis-exercise.pcap -T fields -e ip.dst -e ip.src -e eth.dst -e eth.src | sort | uniq |grep -i 10.0.0.201 --color
-T fields -e ip.src -e dns.qry.name -2R "dns.flags.response eq 0" | awk -F" " '{ print $2 }' | sort -u
-T fields -e ip.src -e dns.qry.name -2R "dns.flags.response eq 0"
tshark -r traffic-analysis-exercise.pcap -Y http.request -T fields -e http.host
tshark -r traffic-analysis-exercise.pcap -Y http.request -T fields -e http.host -e http.user_agent
tshark -r traffic-analysis-exercise.pcap -T fields -e eth.dst eth.src |sort |uniq
tshark -r traffic-analysis-exercise.pcap -T fields -e ip.src -e dns.qry.name |sort |uniq
tshark -r traffic-analysis-exercise.pcap -Y "smb.cmd==0x73"



```


.
