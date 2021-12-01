# Commands used for Incident Response Investigations

[Incident Response Cycle](https://www.sans.org/media/score/504-incident-response-cycle.pdf)

## Linux Commands

[Linux Compromise Assessment Command Cheat Sheet ](https://www.sandflysecurity.com/linux-compromise-detection-command-cheatsheet.pdf)

[Linux Documentation](https://linux.die.net/)

<details><summary><b>Connections</b></summary>
<p>

**Listening ports (all, numeric, pid):**

```
netstat -tulpn
```

```
netstat -nalp
```

---

**External IPs and Ports:**

```
netstat -anltp | awk '{if ($1 !~ /tcp6/ && $4 !~ /^(10|127|0)\.*)/ && $5 !~ /^(10|127|0)\.*/) {print $0}}'
```

</p>
</details>

<details><summary><b>System Logs</b></summary>
<p>

**Recent login of users:**

```
lastlog
```

---

**Check for immutable flags (can't delete w/o removing flag, persistent. Identified by "-i-"):**

```
lsattr -a /bin
```

---

**Check on log rotate:**

```
cat /var/lib/logrotate/status
```

---

**Valid past logins:**

```
cat /var/log/wtmp
```

---

**Bad logins:**

```
cat /var/log/btmp
```

---

**Current logins:**

```
cat /var/log/utmp
```

---

**Check on utmp (traces of log cleaner, i.e. overwritten with nulls):**

```
utmpdump < /var/run/utmp
```

---

**Check for zero byte logs (traces of log cleaners):**

```
ls -al /var/log
```

---

**Key Directories to review:**

```
/tmp/var/log/*
```

---

**Key Files to review:**

```
/var/log/*
cat /var/log/messages
cat /var/log/auth.log
cat /var/log/secure
cat /var/log/boot.log
cat /var/log/dmesg
cat /var/log/kern.log
cat /var/log/faillog
cat /var/log/cron
cat /var/log/yum.log
cat /var/log/maillog
cat /var/log/mail.log
cat /var/log/httpd/
cat /var/log/syslog
and if there's antivirus, important apps, etc.
```

</p>
</details>

<details><summary><b>Processes</b></summary>
<p>

**Monitor processes (esp. high PIDs):**

```
ps -auxwf
ps -aux
ps -ef
```

---

**Display sorted process information:**

```
top
```

---

**Interactive process viewer:**

```
htop
```

---

**Display tree of processes of user or pid:**

```
pstree root
```

---

**List of open files:**

```
lsof -V
```

</p>
</details>

<details><summary><b>Cron</b></summary>
<p>


</p>
</details>

<details><summary><b>Accounts</b></summary>
<p>

</p>
</details>

<details><summary><b>Files</b></summary>
<p>

</p>
</details>

## Windows Commands

[Microsoft Command Documentation](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/windows-commands#n)

[Windows Live Forensics](https://www.youtube.com/watch?v=HcUMXxyYsnw)

[Windows Memory Forensics](https://www.youtube.com/watch?v=cYphLiySAC4)

<details><summary><b>Connections</b></summary>
<p>

**Look at file shares. Make sure each has a defined business purpose:**

```
C:\> net view \\127.0.0.1
```

---

**Open session with machine:**

```
C:\> net session
```

---

**Sessions the machine has opened with other systems:**

```
C:\> net use
```

---

**NETBIOS over TCP/IP activity:**

```
C:\> nbtstat –S
```

---

**Unusual listening TCP and UDP ports:**

```
C:\> netstat –naob
```

---

**Updated and scrolling output of this command every 5 seconds:**

```
C:\> netstat –naob 5
```

---

**Windows Firewall configuration:**

```
C:\> netsh firewall show config
```

</p>
</details>

<details><summary><b>Event Logs</b></summary>
<p>

* **Application**
* **Security**
* **System**

---

**Some Key Windows Events**

| Log Name | Provider Name	| Event IDs	| Description                                               |
| :------: | -------------- | :-------: | :-------------------------------------------------------- | 
| System	 |	              | 7045      |	A service was installed in the system       |
| System	 |                |	7030	    | ...service is marked as an interactive service. However, the system is configured to not allow interactive services. This service may not function properly. |
| System 	 |                |	1056      |	Create RDP certificate |
| System   |                | 10000     | COM Functionality (See SubTee's blog) |
| System   |                | 20001     | Device Driver installation |
| System   |                | 20002     | Remote Access |
| System   |                | 20003     | Service Installation |
| Security |	              |	7045, 10000, 10001, 10100, 20001, 20002, 20003, 24576, 24577, 24579 |	Insert USB |
| Security |	              |	4624	    | Account Logon |
| Security |		            | 4625      |	Failed login |
| Security |	              |	4688      |	Process creation logging |
| Security |		            | 4720	    | A user account was created |
| Security |         		    | 4722      |	A user account was enabled |
| Secutity |                |	4724      | Password reset |
| Secutity |                | 4738      | User account change |
| Security |                |	4728      | A member was added to a security-enabled global group |
| Security |	  	          | 4732      |	A member was added or removed from a security-enabled local group |
| Security |    		        | 1102      |	Clear Event log |
| Application |	EMET	      | 2         |	EMET detected ... mitigation and will close the application: ...exe |
| Firewall |               	|	2003	    | Disable firewall |
| Microsoft-Windows-AppLocker/EXE and DLL |   |	8003 |	(EXE/MSI) was allowed to run but would have been prevented from running if the AppLocker policy were enforced |
| Microsoft-Windows-AppLocker/EXE and DLL |    | 8004	 | (EXE/MSI) was prevented from running. |
| Microsoft-Windows-WindowsDefender/Operational |   |	1116 |	Windows Defender has detected malware or other potentially unwanted software |
| Microsoft-Windows-WindowsDefender/Operational	|   |	1117 |	Windows Defender has taken action to protect this machine from malware or other potentially unwanted software |

---

**Check your logs for suspicious events, such as:**

* "User failed/successful logon/logoff events"
* "New user accounts, changes to user accounts,groups, etc."
* "Service started or stopped"
* “Event log service was stopped.”
* “Windows File Protection is not active on this system.”
* "The protected System file [file name] was not restored to its original, valid version because the Windows File Protection..."
* “The MS Telnet Service has started successfully.”

**Look for large number of failed logon attempts or locked out accounts.**

---

**Windows event viewer through the GUI:**

```
C:\> eventvwr.msc
```

---

**Using the command prompt:**

```
C:\> eventquery.vbs | more
```

---

**Or, to focus on a particular event log:**

```
C:\> eventquery.vbs /L security
```

</p>
</details>

<details><summary><b>Processes and Services</b></summary>
<p>

**Look for unusual/unexpected processes, and focus on processes with User Name “SYSTEM” or “Administrator” (or users in the
Administrators' group). You need to be familiar with normal processes and services and search for deviations.**

---

**Run Task Manager for GUI view:**

```
C:\> taskmgr.exe
```

---

**Task Manager using Command Prompt:**

```
C:\> tasklist
C:\> wmic process list full
```

---

**Look for unusual services**

**Run Services for GUI view:**

```
C:\> services.msc
```

---

**Services using the command prompt:**

```
C:\> net start
C:\> sc query
```

---

**Get a list of services and disable or stop:**

```
C:\> sc query
C:\> sc config "<SERVICE NAME>" start= disabled
C:\> sc STOP "<SERVICE NAME>"
C:\> wmic servce where name='<SERVICE NAME>' call ChangeStartmode Disabled
```

---

**List of services and associated with each process**

```
C:\> tasklist /svc
```

</p>
</details>

<details><summary><b>Scheduled Tasks</b></summary>
<p>

**Look for unusual scheduled tasks, especially those that run as a user in the Administrators group, as
SYSTEM, or with a blank user name. Using the GUI, run Task Scheduler: Start > Programs > Accessories > System
Tools > Scheduled Tasks**

```
C:\> schtasks
```

**Check other autostart items as well for unexpected entries, remembering to check user autostart directories and registry keys.**

**Run msconfig and lookup at the Startup tab. Start > Run > Type msconfig.exe**

---

**View startup information via WMI:**

```
C:\> wmic startup list full
```

</p>
</details>

<details><summary><b>Registry</b></summary>
<p>

**Look for strange programs referred to in registry keys associated with system start up:**

* HKLM\Software\Microsoft\Windows\CurrentVersion\Run
* HKLM\Software\Microsoft\Windows\CurrentVersion\Runonce
* HKLM\Software\Microsoft\Windows\CurrentVersion\RunonceEx

**Note that you should also check the HKCU counterparts (replace HKLM with HKCU above).**

---

**Registry GUI:**

```
C:\> regedit
```

---

**Registry via the command prompt:**

```
C:\> reg query <reg key>
```

</p>
</details>

<details><summary><b>Accounts</b></summary>
<p>

**Look for new, unexpected accounts in the Administrators group. Click on Groups, Double Click on Administrators, then
check members of this group.**

```
C:\> lusrmgr.msc
```

---

**Check administrators from the command prompt:**

```
C:\> net user
C:\> net localgroup administrators
```

---

**User information:**

```
C:\> whoami
C:\> net users
C:\> net group administrators
C:\> wmic rdtoggle list
C:\> wmic useraccount list
C:\> wmic group list
C:\> wmic netlogin get name, lastlogon, badpasswordcount
C:\> wmic netclient list brief
C:\> doskey /history > history.txt
```

</p>
</details>

<details><summary><b>Files</b></summary>
<p>

**Check file space usage to look for sudden major decreases in free space, using the GUI (right-click on partition), or type:**

```
C:\> dir c:\
```

**Look for unusually big files: Start > Search > For Files of Folders > Search Options > Size > At Least 10000KB**

</p>
</details>

## tcpdump

<details><summary><b>Syntax</b></summary>
<p>

```
tcpdump	[-aAenStvxX] [-F filterfile] [-i int] [-c n] [-r pcapfile] [-s snaplen] [-w pcapfile] [‘bpf filter’]
```

```
-A     display payload
-c n   display first n packets
-D     list interfaces
-e     display data link header
-F     read filter expression from file
-i     listen on specified interface
-n     do not resolve IP addresses / ports
-r     read packets from file
-s     set snap length in bytes
-S     display absolute TCP sequence numbers
-t     don't print timestamp
-tttt  print date and time
-v     verbose (multiple v: more verbose)
- w    write packets to file
-x     display in hex
-xx    display link layer in hex
-X     display in hex + ASCII
```

</p>
</details>

<details><summary><b>Commands</b></summary>
<p>

**View Traffic with timestamps, don't convert addresses, and be verbose:**

`tcpdump -tttt -n -vv`

---

**Find the top talkers after 1000 packets (Potential DDOS):**

`tcpdump -nn -c 1000 | awk '{print $3}' | cut -d. -f1-4 | sort-n | uniq -c | sort -nr`

---

**Capture traffic on any interface from a target host and specific port and output to a file:**

`tcpdump -w <FILENAME>.pcap -i any dst <TARGET IP ADDRESS> and port 80`

---

**View traffic only between two hosts:**

`tcpdump host 10.0.0.1 && host 10.0.0.2`

---

**View all traffic except from a net and a host:**

`tcpdump not net 10.10 && not host 192.168.1.2`

---

**View host and either of two other hosts:**

`tcpdump host 10.10.10.10 && \(10.10.10.20 or 10.10.10.30\)`

---

**Save pcap file on rotating size:**

`tcpdump -n -s65535 -C 1000 -w '%host_%Y-%m-%d_%H:%M:%S.pcap`

---

**Save pcap file to a remote host:**

`tcpdump -w | ssh <REMOTE HOST ADDRESS> -p 50005 "cat - > /tmp/remotecapture.pcap"`

---

**Grab traffic that contains the word pass:**

`tcpdump -n -A -s0 | grep pass`

---

**Grab many clear text protocols passwords:**

`tcpdump -n -A s0 port http or port ftp or port smtp or port imap or port pop3 or port telnet | egrep -i 'pass=|pwd=|log=|login=|user=|pw=|passw=|passwd=|password=|pass:|user:|username:|password:|login:|pass |user ' --color=auto --line-buffered -B20`

---

**Get throughput:**

`tcpdump -w - |pv -bert >/dev/null`

---

**Filter out IPv6 traffic:**

`tcpdump not ip6`

---

**Filter out IPv4:**

`tcpdump ip6`

---

**Find traffic with evil bit: There’s a bit in the IP header that never gets set by legitimate applications, which we call the “Evil Bit”. Here’s a fun filter to find packets where it’s been toggled.**

`tcpdump 'ip[6] & 128 != 0'`

---

**Look for suspicious and self-signed SSL certificates:**

`tcpdump -s 1500 -A '(tcp[((tcp[12:1] & 0xf0) >> 2)+5:1] = 0x01) and (tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16)'`

</p>
</details>

## TShark

<details><summary><b>Commands</b></summary>
<p>

**List of network interfaces:**

`tshark -D`

---

**Listen on multiple network interfaces:**

`tshark -i eth1 -i eth2 -i eth3`

---

**Save to pcap file and disable name resolution:**

`tshark -nn -w <FILENAME>.pcap`

---

**Get absolute date and time stamp:**

`tshark -t a`

---

**Get arp or icmp traffic:**

`tshark arp or icmp`

</p>
</details>
