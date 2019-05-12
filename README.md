# Commands used for Incident Response Investigations

## Linux Commands

<details><summary><b>Connections</b></summary>
<p>

**Listening ports (all, numeric, pid):**

`
netstat -tulpn
`

`
netstat -nalp
`

**External IPs and Ports:**

`
netstat -anltp | awk '{if ($1 !~ /tcp6/ && $4 !~ /^(10|127|0)\.*)/ && $5 !~ /^(10|127|0)\.*/) {print $0}}'
`

</p>
</details>

<details><summary><b>System Logs</b></summary>
<p>

**Recent login of users:**

`
lastlog
`

**Check for immutable flags (can't delete w/o removing flag, persistent. Identified by "-i-"):**

`
lsattr -a /bin
`

**Check on log rotate:**

`
cat /var/lib/logrotate/status
`

**Valid past logins:**

`
cat /var/log/wtmp
`

**Bad logins:**

`
cat /var/log/btmp
`

**Current logins:**

`
cat /var/log/utmp
`

**Check on utmp (traces of log cleaner, i.e. overwritten with nulls):**

`
utmpdump < /var/run/utmp
`

**Check for zero byte logs (traces of log cleaners):**

`
ls -al /var/log
`

**Key Directories to review:**

`
/tmp
/var/log/*
`

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

`
ps -auxwf
ps -aux
ps -ef
`

**Display sorted process information:**

`
top
`

**Interactive process viewer:**

`
htop
`

**Display tree of processes of user or pid:**

`
pstree root
`

**List of open files:**

`
lsof -V
`

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

## Windows Commands

<details><summary><b>Connections</b></summary>
<p>

**Look at file shares. Make sure each has a defined business purpose:**

`
C:\> net view \\127.0.0.1
`

**Open session with machine:**

`
C:\> net session
`

**Sessions the machine has opened with other systems:**

`
C:\> net use
`

**NETBIOS over TCP/IP activity:**

`
C:\> nbtstat –S
`

Unusual listening TCP and UDP ports:

`
C:\> netstat –naob
`

Updated and scrolling output of this command every 5 seconds:

`
C:\> netstat –naob 5
`

**Windows Firewall configuration:**

`
C:\> netsh firewall show config
`

</p>
</details>

<details><summary><b>System Logs</b></summary>
<p>


</p>
</details>

<details><summary><b>Processes</b></summary>
<p>


</p>
</details>

<details><summary><b>Scheduled Tasks</b></summary>
<p>


</p>
</details>

<details><summary><b>Accounts</b></summary>
<p>


</p>
</details>
