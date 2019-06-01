# Commands used for Incident Response Investigations

## Linux Commands

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

* Application
* Security
* System

---

**Check your logs for suspicious events, such as:**

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

## TCPDUMP

## Wireshark
