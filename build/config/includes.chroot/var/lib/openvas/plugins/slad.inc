###############################################################################
# OpenVAS Vulnerability Test Support File
#
# Support functions for SLAD queries
#
# Authors:
# Dirk Jagdmann
# Michael Wiegand
#
# Changes:
# Thomas Rotter
#
# Copyright:
# Copyright (c) 2005 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
################################################################################

function init_add_preferences () {
  script_add_preference (name: "Execute Tripwire HIDS to check system's file integrity (Linux only)", type: "checkbox", value: "no");
  script_add_preference (name: "Execute ClamAV to search for virus-infected files (Linux only)", type: "checkbox", value: "no");
  script_add_preference (name: "ClamAV level", type: "radio", value: "Move infected files to quarantine;Remove infected files;Move infected files to quarantine exclude archives (.zip, .tgz, etc);Remove infected files exclude archives (.zip, .tgz, etc)");
  script_add_preference (name: "Execute LSOF to retrieve a list of open files (Linux only)", type: "checkbox", value: "no");
  script_add_preference (name: "Execute Tiger for various checks (Linux only)", type: "checkbox", value: "no");
  script_add_preference (name: "tiger level", type: "radio", value: "Checks user and passwd on local system;Check Filesystem Permissions;Check Systems Configuration and applications;Check running System and Processes;Perform all Tiger checks on system");
  script_add_preference (name: "Analyse Syslog-Files for security incidents (Linux only)", type: "checkbox", value: "no");
  script_add_preference (name: "syslogwatch level", type: "radio", value: "Analyse SysLogs low detail;Analyse SysLogs medium detail;Analyse SysLogs high detail");
  script_add_preference (name: "fetch hardware MB sensors (Linux only)", type: "checkbox", value: "no");
  script_add_preference (name: "Execute John-the-Ripper to find weak user passwords", type: "checkbox", value: "no");
  script_add_preference (name: "john level", type: "radio", value: "Fast-Crack;Dictionary Mode (slow);Full-Crack (very slow)");
  script_add_preference (name: "Execute ovaldi for scanning OVAL described issues", type: "checkbox", value: "no");
  script_add_preference (name: "ovaldi report format", type: "radio", value: "Text;HTML");
  script_add_preference (name: "Analyse SNMP-Traps collected by snmptrapd (Linux only)", type: "checkbox", value: "no");
  script_add_preference (name: "Fetch Snort-Events from the Snort MYSQL/MSSQL Database", type: "checkbox", value: "no");
  script_add_preference (name: "Execute ssh vulnkey to detect unsecure SSH RSA and DSA keys from broken Debian OpenSSL pkt (Linux only)", type: "checkbox", value: "no");
  script_add_preference (name: "Execute ChkRootKit to find installed rootkits (Linux only)", type: "checkbox", value: "no");
  script_add_preference (name: "Execute Netstat to Displays all connections and listening ports. (Windows only)", type: "checkbox", value: "no");
  script_add_preference (name: "netstat level", type: "radio", value: "udp/tcp and udpv6/tcpv6;tcp and tcpv6;udp and udpv6");
  script_add_preference (name: "Execute SFC to Scan integrity of all protected system files. This Funktion will only work on (Windows Vista/2008 and later)", type: "checkbox", value: "no");
  script_add_preference (name: "Execute Microsoft Baseline Security Analyzer (Windows only)", type: "checkbox", value: "no");
  script_add_preference (name: "MBSA level", type: "radio", value: "Run MBSA and check only for missing updates on Windows Update;Run MBSA and check only for missing updates on WSUS;Run MBSA and check only local Userpasswords;Run MBSA and check the OS;Run MBSA and check only InternetInformationServer;Run MBSA and check only SQL Server;Run MBSA and perform all Tests");


}

function get_slad_plugins(sock, slad_exe){
  slad_cmd = slad_exe + " -s plugins";
  val = ssh_cmd (socket: sock, cmd: slad_cmd, timeout: 60);
  Lst = split(val, keep:0);
  for(i=0; i<max_index(Lst); i++){
    if (Lst[i] =~ "e:0:.*") plugins += Lst[i] + '\n';
  }
if (!plugins) plugins = val;
return plugins;
}

function check_and_run_slad_plugins(sock, slad_exe, runlevel, run){
  val = get_slad_plugins(sock:sock, slad_exe:slad_exe);
  desc = get_slad_description (entry:runlevel);
  shortdesc = get_slad_short_description (entry:runlevel);
  if (run == "yes" && runlevel >< val){
    slad_cmd = slad_exe + " -r " + runlevel;
    sladresult = ssh_cmd (socket: sock, cmd: slad_cmd, timeout: 60);
    if ("200 queued" >< sladresult) result = shortdesc + ':\tThe Plugins was started.\n';
    else if ("403 plugin already running" >< sladresult) result = shortdesc + ':\tThe Plugin is already running.\n';
    else result = desc +':\n' + sladresult;
  }else if (run == "yes" && runlevel >!< val){
    result = shortdesc + ':\tThe Plugin was not present on target system, but selected to execute.\n';
  }else if(run == "no" && runlevel >< val){
    result = shortdesc + ':\tThe Plugin was present on target system, but not selected to execute.\n';
  }else if(run == "no" && runlevel >!< val){
    result = shortdesc + ':\tThe Plugin was not present on target system and not selected to execute.\n';
  }else result = sladresult;
return result;
}

function run_slad (sock, slad_exe) {

  # chkrootkit
  run = script_get_preference ("Execute ChkRootKit to find installed rootkits (Linux only)");
  runlevel = "chkrootkit:chkrootkit:normal";
  results += check_and_run_slad_plugins (sock:sock, slad_exe:slad_exe, runlevel:runlevel, run:run);

  # ClamAV
  run = script_get_preference ("Execute ClamAV to search for virus-infected files (Linux only)");
  level = script_get_preference ("ClamAV level");
  if (level == "Move infected files to quarantine") runlevel = "ClamAV:ClamAVQua:QuarantClamAV";
  else if (level == "Remove infected files") runlevel = "ClamAV:ClamAVDel:DeleteClamAV";
  else if (level == "Move infected files to quarantine exclude archives (.zip, .tgz, etc)") runlevel = "ClamAV:ClamAVNoArch:QuarantClamAVNoArch";
  else if (level == "Remove infected files exclude archives (.zip, .tgz, etc)") runlevel = "ClamAV:ClamAVDelNoArch:DeleteClamAVNoArch";
  results += check_and_run_slad_plugins (sock:sock, slad_exe:slad_exe, runlevel:runlevel, run:run);

  # hardware MB sensors
  run = script_get_preference ("fetch hardware MB sensors (Linux only)");
  runlevel = "sensors:sensors:sensors";
  results += check_and_run_slad_plugins (sock:sock, slad_exe:slad_exe, runlevel:runlevel, run:run);

  # john
  run = script_get_preference ("Execute John-the-Ripper to find weak user passwords");
  level = script_get_preference ("john level");
  if (level == "Fast-Crack") runlevel = "john:fastjohn:fastjohn";
  else if (level == "Dictionary Mode (slow)") runlevel = "john:dictjohn:dictjohn";
  else if (level == "Full-Crack (very slow)") runlevel = "john:fulljohn:fulljohn";
  results += check_and_run_slad_plugins (sock:sock, slad_exe:slad_exe, runlevel:runlevel, run:run);

  # lsof
  run = script_get_preference ("Execute LSOF to retrieve a list of open files (Linux only)");
  runlevel = "lsof:lsof:lsof";
  results += check_and_run_slad_plugins (sock:sock, slad_exe:slad_exe, runlevel:runlevel, run:run);

  # MBSA
  run = script_get_preference ("Execute Microsoft Baseline Security Analyzer (Windows only)");
  level = script_get_preference ("MBSA level");
  if (level == "Run MBSA and check only for missing updates on Windows Update") runlevel = "MBSA:updates:mbsaupdates";
  else if (level == "Run MBSA and check only for missing updates on WSUS")  runlevel = "MBSA:wsusupdates:mbsawsusupdates";
  else if (level == "Run MBSA and check only local Userpasswords") runlevel = "MBSA:password:mbsapassword";
  else if (level == "Run MBSA and check the OS") runlevel = "MBSA:os:mbsaos";
  else if (level == "Run MBSA and check only InternetInformationServer") runlevel = "MBSA:iis:mbsaiis";
  else if (level == "Run MBSA and check only SQL Server") runlevel = "MBSA:sql:mbsasql";
  else if (level == "Run MBSA and perform all Tests") runlevel = "MBSA:all:mbsaall";
  results += check_and_run_slad_plugins (sock:sock, slad_exe:slad_exe, runlevel:runlevel, run:run);

  # netstat
  run = script_get_preference ("Execute Netstat to Displays all connections and listening ports. (Windows only)");
  level = script_get_preference ("netstat level");
  if (level == "udp/tcp and udpv6/tcpv6") runlevel = "Netstat:na:netstat-na";
  else if (level == "tcp and tcpv6")  runlevel = "Netstat:natcp:netstat-natcp";
  else if (level == "udp and udpv6") runlevel = "Netstat:naudp:netstat-naudp";
  results += check_and_run_slad_plugins (sock:sock, slad_exe:slad_exe, runlevel:runlevel, run:run);

  # ovaldi
  run = script_get_preference ("Execute ovaldi for scanning OVAL described issues");
  report_format = script_get_preference("ovaldi report format");
  if (report_format == "Text") runlevel = "ovaldi:short:short";
  else if (report_format == "HTML") runlevel = "ovaldi:html:html";
  results += check_and_run_slad_plugins (sock:sock, slad_exe:slad_exe, runlevel:runlevel, run:run);

  # tiger
  run = script_get_preference ("Execute Tiger for various checks (Linux only)");
  level = script_get_preference ("tiger level");
  if (level == "Checks user and passwd on local system") runlevel = "tiger:tigeruser:tigeruser";
  else if (level == "Check Filesystem Permissions") runlevel = "tiger:tigerperm:tigerperm";
  else if (level == "Check Systems Configuration and applications") runlevel = "tiger:tigerconfig:tigerconfig";
  else if (level == "Check running System and Processes") runlevel = "tiger:tigersystem:tigersystem";
  else if (level == "Perform all Tiger checks on system") runlevel = "tiger:fulltiger:fulltiger";
  results += check_and_run_slad_plugins (sock:sock, slad_exe:slad_exe, runlevel:runlevel, run:run);

  # tripwire
  run = script_get_preference ("Execute Tripwire HIDS to check system's file integrity (Linux only)");
  runlevel = "tripwire:tripwire:tripwire";
  results += check_and_run_slad_plugins (sock:sock, slad_exe:slad_exe, runlevel:runlevel, run:run);

  # SFC
  run = script_get_preference ("Execute SFC to Scan integrity of all protected system files. This Funktion will only work on (Windows Vista/2008 and later)");
  runlevel = "SFC:verifyonly:sfcverifyonly";
  results += check_and_run_slad_plugins (sock:sock, slad_exe:slad_exe, runlevel:runlevel, run:run);

  # snmptrapwatch
  run = script_get_preference ("Analyse SNMP-Traps collected by snmptrapd (Linux only)");
  runlevel = "snmptrapwatch:snmptrapwatch:trapwatch";
  results += check_and_run_slad_plugins (sock:sock, slad_exe:slad_exe, runlevel:runlevel, run:run);

  # snort
  run = script_get_preference ("Fetch Snort-Events from the Snort MYSQL/MSSQL Database");
  runlevel = "snort:snort:snort";
  results += check_and_run_slad_plugins (sock:sock, slad_exe:slad_exe, runlevel:runlevel, run:run);

  # sshvulnkey
  run = script_get_preference ("Execute ssh vulnkey to detect unsecure SSH RSA and DSA keys from broken Debian OpenSSL pkt (Linux only)");
  runlevel = "sshvulnkey:sshvuln:normal";
  results += check_and_run_slad_plugins (sock:sock, slad_exe:slad_exe, runlevel:runlevel, run:run);

  # syslogwatch
  run = script_get_preference ("Analyse Syslog-Files for security incidents (Linux only)");
  level = script_get_preference ("syslogwatch level");
  if (level == "Analyse SysLogs low detail") runlevel = "syslogwatch:logwatchlow:logwatchlow";
  else if (level == "Analyse SysLogs medium detail") runlevel = "syslogwatch:logwatchmed:logwatchmed";
  else if (level == "Analyse SysLogs high detail") runlevel = "syslogwatch:logwatchhigh:logwatchhigh";
  results += check_and_run_slad_plugins (sock:sock, slad_exe:slad_exe, runlevel:runlevel, run:run);


  if (results) security_note (data: results);
  else log_message (data: string('SLAD Run: No result was fetched. Perhaps no test has been selected?'));
}

function get_slad_description (entry) {
  if (entry == "tripwire:tripwire:tripwire") return "Execute Tripwire HIDS to check system's file integrity";
  else if (entry == "ClamAV:ClamAVQua:QuarantClamAV") return "Execute ClamAV to search for virus-infected files: Move infected files to quarantine";
  else if (entry == "ClamAV:ClamAVDel:DeleteClamAV") return "Execute ClamAV to search for virus-infected files: Remove infected files";
  else if (entry == "ClamAV:ClamAVNoArch:QuarantClamAVNoArch") return "Execute ClamAV to search for virus-infected files: Move infected files to quarantine exclude archives (.zip, .tgz, etc)";
  else if (entry == "ClamAV:ClamAVDelNoArch:DeleteClamAVNoArch") return "Execute ClamAV to search for virus-infected files: Remove infected files exclude archives (.zip, .tgz, etc)";
  else if (entry == "lsof:lsof:lsof") return "Execute LSOF to retrieve a list of open files";
  else if (entry == "tiger:tigeruser:tigeruser") return "Execute Tiger for various checks: Checks user and passwd on local system";
  else if (entry == "tiger:tigerperm:tigerperm") return "Execute Tiger for various checks: Check Filesystem Permissions";
  else if (entry == "tiger:tigerconfig:tigerconfig") return "Execute Tiger for various checks: Check Systems Configuration and applications";
  else if (entry == "tiger:tigersystem:tigersystem") return "Execute Tiger for various checks: Check running System and Processes";
  else if (entry == "tiger:fulltiger:fulltiger") return "Execute Tiger for various checks: Perform all Tiger checks on system";
  else if (entry == "syslogwatch:logwatchlow:logwatchlow") return "Analyse Syslog-Files for security incidents: Analyse SysLogs low detail";
  else if (entry == "syslogwatch:logwatchmed:logwatchmed") return "Analyse Syslog-Files for security incidents: Analyse SysLogs medium detail";
  else if (entry == "syslogwatch:logwatchhigh:logwatchhigh") return "Analyse Syslog-Files for security incidents: Analyse SysLogs high detail";
  else if (entry == "sensors:sensors:sensors") return "fetch hardware MB sensors";
  else if (entry == "john:fastjohn:fastjohn") return "Execute John-the-Ripper to find weak user passwords: Fast-Crack";
  else if (entry == "john:dictjohn:dictjohn") return "Execute John-the-Ripper to find weak user passwords: Dictionary Mode (slow)";
  else if (entry == "john:fulljohn:fulljohn") return "Execute John-the-Ripper to find weak user passwords: Full-Crack (very slow)";
  else if (entry == "ovaldi:short:short") return "Execute ovaldi for scanning OVAL described issues: Text Report";
  else if (entry == "ovaldi:html:html") return "Execute ovaldi for scanning OVAL described issues: HTML Report";
  else if (entry == "snmptrapwatch:snmptrapwatch:trapwatch") return "Analyse SNMP-Traps collected by snmptrapd: SNMP Traps in the daemon.log";
  else if (entry == "snort:snort:snort") return "Fetch Snort-Events from the Snort MYSQL/MSSQL Database";
  else if (entry == "sshvulnkey:sshvuln:normal") return "Execute ssh vulnkey to detect unsecure SSH RSA and DSA keys from broken Debian OpenSSL pkt";
  else if (entry == "chkrootkit:chkrootkit:normal") return "Execute ChkRootKit to find installed rootkits";
  else if (entry == "Netstat:na:netstat-na") return "Execute Netstat to Displays all tcp/tcpv6 and udp/udpv6 connections and listening ports";
  else if (entry == "Netstat:natcp:netstat-natcp") return "Execute Netstat to Displays all tcp/tcpv6 connections and listening ports";
  else if (entry == "Netstat:naudp:netstat-naudp") return "Execute Netstat to Displays all udp/udpv6 connections and listening ports";
  else if (entry == "SFC:verifyonly:sfcverifyonly") return "Execute Microsoft Windows Resource Checker. No repair operation will performed";

  else if (entry == "MBSA:updates:mbsaupdates") return "Execute Microsoft Baseline Security Analyzer and check only for missing updates on Windows Update";
  else if (entry == "MBSA:wsusupdates:mbsawsusupdates") return "Execute Microsoft Baseline Security Analyzer and check only for missing updates on WSUS";
  else if (entry == "MBSA:password:mbsapassword") return "Execute Microsoft Baseline Security Analyzer and check only local Userpasswords";
  else if (entry == "MBSA:os:mbsaos") return "Execute Microsoft Baseline Security Analyzer and check the OS";
  else if (entry == "MBSA:iis:mbsaiis") return "Execute Microsoft Baseline Security Analyzer and check only InternetInformationServer";
  else if (entry == "MBSA:sql:mbsasql") return "Execute Microsoft Baseline Security Analyzer and check only SQL Server";
  else if (entry == "MBSA:all:mbsaall") return "Execute Microsoft Baseline Security Analyzer and perform all Tests";
}

function get_slad_short_description (entry) {
  if (entry =~ "tripwire:.*") return "Tripwire HIDS";
  else if (entry =~ "ClamAV:.*") return "ClamAV";
  else if (entry =~ "lsof:.*") return "LSOF";
  else if (entry =~ "tiger:.*") return "Tiger";
  else if (entry =~ "syslogwatch:.*") return "SyslogWatch";
  else if (entry =~ "sensors:.*") return "Hardware MB sensors";
  else if (entry =~ "john:.*") return "John-the-Ripper";
  else if (entry =~ "ovaldi:.*") return "Ovaldi";
  else if (entry =~ "snmptrapwatch:.*") return "Snmptrapd";
  else if (entry =~ "snort:.*") return "Snort";
  else if (entry =~ "sshvulnkey:.*") return "ssh vulnkey";
  else if (entry =~ "chkrootkit:.*") return "ChkRootKit";
  else if (entry =~ "Netstat:.*") return "Netstat";
  else if (entry =~ "SFC:.*") return "SFC";
  else if (entry =~ "MBSA:.*") return "MBSA";
}

function dump_preferences () {
  display ("tripwire: ", script_get_preference ("Execute Tripwire HIDS to check system's file integrity (Linux only)"), "\n");
  display ("ClamAV: ", script_get_preference ("Execute ClamAV to search for virus-infected files (Linux only)"), "\n");
  display ("  level: ", script_get_preference ("ClamAV level"), "\n");
  display ("lsof: ", script_get_preference ("Execute LSOF to retrieve a list of open files (Linux only)"), "\n");
  display ("tiger: ", script_get_preference ("Execute Tiger for various checks (Linux only)"), "\n");
  display ("  level: ", script_get_preference ("tiger level"), "\n");
  display ("syslogwatch: ", script_get_preference ("Analyse Syslog-Files for security incidents (Linux only)"), "\n");
  display ("  level: ", script_get_preference ("syslogwatch level"), "\n");
  display ("sensors: ", script_get_preference ("fetch hardware MB sensors"), "\n");
  display ("john: ", script_get_preference ("Execute John-the-Ripper to find weak user passwords"), "\n");
  display ("  level: ", script_get_preference ("john level"), "\n");
  display ("ovaldi: ", script_get_preference ("Execute ovaldi for scanning OVAL described issues"), "\n");
  display ("snmptrapwatch: ", script_get_preference ("Analyse SNMP-Traps collected by snmptrapd (Linux only)"), "\n");
  display ("snort: ", script_get_preference ("Fetch Snort-Events from the Snort MYSQL/MSSQL Database"), "\n");
  display ("sshvulnkey: ", script_get_preference ("Execute ssh vulnkey to detect unsecure SSH RSA and DSA keys from broken Debian OpenSSL pkt (Linux only)"), "\n");
  display ("chkrootkit: ", script_get_preference ("Execute ChkRootKit to find installed rootkits (Linux only)"), "\n");
  display ("netstat: ", script_get_preference ("Execute Netstat to Displays all connections and listening ports. (Windows only)"), "\n");
  display ("SFC: ", script_get_preference ("Execute SFC to Scan integrity of all protected system files. This Funktion will only work on (Windows Vista/2008 and later)"), "\n");
  display ("MBSA: ", script_get_preference ("Execute Microsoft Baseline Security Analyzer (Windows only)"), "\n");
}
