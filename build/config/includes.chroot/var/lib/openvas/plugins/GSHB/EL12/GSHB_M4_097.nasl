###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_097.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 12. EL, Maﬂnahme 4.097
#
# Authors:
# Thomas Rotter <thomas.rotter@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "IT-Grundschutz M4.097: Ein Dienst pro Server (Win).

Diese Pr¸fung bezieht sich auf die 12. Erg‰nzungslieferung (12. EL) des IT-
Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04097.html";


if(description)
{
  script_id(94059);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2011-11-07 13:38:53 +0100 (Mon, 07 Nov 2011)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.097: Ein Dienst pro Server (Win)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("IT-Grundschutz M4.097: Ein Dienst pro Server (Win).");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-12");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-12");
  script_dependencies("GSHB/GSHB_WMI_OSInfo.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.097: Ein Dienst pro Server (Win)\n';

gshbm =  "IT-Grundschutz M4.097: ";

OSVER = get_kb_item("WMI/WMI_OSVER");
OSTYPE = get_kb_item("WMI/WMI_OSTYPE");
OSNAME = get_kb_item("WMI/WMI_OSNAME");
log = get_kb_item("WMI/WMI_OS/log");
WMIOSLOG = get_kb_item("WMI/WMI_OS/log");

include("wmi_svc.inc");
include("wmi_user.inc");
include("wmi_misc.inc");

host    = get_host_ip();
usrname = get_kb_item("SMB/login");
domain  = get_kb_item("SMB/domain");
if (domain){
  usrname = domain + '\\' + usrname;
}
passwd  = get_kb_item("SMB/password");

if(host && usrname && passwd){
 handle = wmi_connect(host:host, username:usrname, password:passwd); 
 
 vhdsvc = wmi_svc_prop(handle:handle, svcName:"vhdsvc");
 nvspwmi = wmi_svc_prop(handle:handle, svcName:"nvspwmi");
 vmms = wmi_svc_prop(handle:handle, svcName:"vmms");
 
 if (vhdsvc){
   val = split(vhdsvc, "\n", keep:0);
   for(i=1; i<max_index(val); i++)
   {
     if ("Caption =" >< val[i]) vhdsvc_cap = val[i] - "Caption = ";
     else if ("Started =" >< val[i])vhdsvc_started = val[i] - "Started = ";
     else if ("StartMode =" >< val[i])vhdsvc_startmode = val[i] - "StartMode = ";
     else if ("State =" >< val[i])vhdsvc_state = val[i] - "State = ";
   }
 }
 if (nvspwmi){
   val = split(nvspwmi, "\n", keep:0);
   for(i=1; i<max_index(val); i++)
   {
     if ("Caption =" >< val[i]) nvspwmi_cap = val[i] - "Caption = ";
     else if ("Started =" >< val[i])nvspwmi_started = val[i] - "Started = ";
     else if ("StartMode =" >< val[i])nvspwmi_startmode = val[i] - "StartMode = ";
     else if ("State =" >< val[i])nvspwmi_state = val[i] - "State = ";
   }
 }
 if (vmms){
   val = split(vmms, "\n", keep:0);
   for(i=1; i<max_index(val); i++)
   {
     if ("Caption =" >< val[i]) vmms_cap = val[i] - "Caption = ";
     else if ("Started =" >< val[i])vmms_started = val[i] - "Started = ";
     else if ("StartMode =" >< val[i])vmms_startmode = val[i] - "StartMode = ";
     else if ("State =" >< val[i])vmms_state = val[i] - "State = ";
   }
 }
}
ports = get_kb_list("Ports/tcp/*");
portchecklist = make_list("21", "22", "23", "25", "42", "66", "80", "102", "109", "110", "115", "118",
"119", "143", "270", "465", "548", "554", "563", "992", "993", "995", "1270", "1433", "1434", "1723", "1755", "2393", "2394", "2725", "8080", "51515");

PORTTITEL = "
21 = File Transfer Protocol (FTP)
22 = Secure Shell (SSH) Protocol
23 = Telnet
25 = Simple Mail Transfer (SMTP)
42 = Windows Internet Name Service (WINS)
66 = Oracle SQL*NET
80 = World Wide Web (HTTP)
102 = Microsoft Exchange MTA Stacks (X.400)
109 = Post Office Protocol - Version 2 (POP2)
110 = Post Office Protocol - Version 3 (POP3)
115 = Simple File Transfer Protocol (SFTP)
118 = SQL Services
119 = Network News Transfer Protocol (NNTP)
143 = Internet Message Access Protocol (IMAP4)
270 = Microsoft Operations Manager 2004
465 = Simple Mail Transfer over SSL (SMTPS)
548 = File Server for Macintosh
554 = Windows Media Services
563 = Network News Transfer Protocol over TLS/SSL (NNTPS)
992 = Telnet ¸ber TLS/SSL
993 = IMAP4 ¸ber TLS/SSL (IMAP4S)
995 = POP3 ¸ber TLS/SSL (POP3S)
1270 = MOM-Encrypted Microsoft Operations Manager 2000
1433 = Microsoft-SQL-Server
1434 = Microsoft-SQL-Monitor
1723 = Routing and Remote Access (PPTP)
1755 = Windows Media Services (MMS)
2393 = OLAP Services 7.0 SQL Server: Downlevel OLAP Client Support
2394 = OLAP Services 7.0 SQL Server: Downlevel OLAP Client Support
2725 = SQL Analysis Services SQL 2000 Analysis Server
8080 = HTTP Alternative
51515 = MOM-Clear Microsoft Operations Manager 2000
";

foreach port (keys(ports))
{
   port = int(port - 'Ports/tcp/');
   portlist = portlist + port + '|';
}

if (WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System."){
  result = string("nicht zutreffend");
  desc = string("Auf dem System l‰uft Samba, es ist kein\nMicrosoft Windows System.");
}else if("none" >< OSVER){
  result = string("Fehler");
  if (!log)desc = string("Beim Testen des Systems trat ein Fehler auf.");
  if (log)desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
}else if(OSVER == '5.1' || (OSVER == '5.2' && OSNAME >< 'Microsoft(R) Windows(R) XP Professional x64 Edition') || (OSVER == '6.0' && OSTYPE == 1 ) || (OSVER == '6.1' && OSTYPE == 1 )){
  result = string("nicht zutreffend");
  desc = string("Das System ist kein Server.");
}
else
{
  checkport = split(portlist, sep:"|", keep:0);
  for (c=0; c<max_index(checkport); c++)
  {
    for (p=0; p<max_index(portchecklist); p++)
    {
      if (checkport[c] == portchecklist[p]){
        PORTNAME = egrep(pattern:'^' + checkport[c] + ' = ', string:PORTTITEL);
        PORTNAME = ereg_replace(pattern:'\n',replace:'', string:PORTNAME);
        RES = RES + "Port: " + PORTNAME + ';\n';
        CHECK = CHECK + 1;
      }
    }
  }
  if (vhdsvc_cap && nvspwmi_cap && vmms_cap){
    if (vhdsvc_state == "Running" &&  nvspwmi_state == "Running" &&  vmms_state == "Running"){
      if (RES)
      {
        result = string("nicht erf¸llt");
        desc = string('Auf dem Server wurde folgende Virtualisierungssoftware\ngefunden:\n' + vmms_cap + '\nFolgende(r) Dienst l‰uft neben der Virtualisierungssoftware\nauf dem Server:\n' + RES);
      }
      else
      {
        result = string("erf¸llt");
        desc = string('Auf dem Server wurde folgende Virtualisierungssoftware\ngefunden:\n'+ vmms_cap + '\nAuf dem Server laufenen keine weiteren zu ¸berpr¸fenden\nDienste.');
      }
    }
  }
  else if (CHECK > 1)
  {
    result = string("nicht erf¸llt");
    desc = string('Folgende Dienste laufen auf dem Server:\n') + RES;
    desc = desc + string ('\nPr¸fen Sie bitte ob alle Dienste nˆtig sind.');
  }
  else if (RES)
  {
    result = string("erf¸llt");
    desc = string('Folgender Dienst l‰uft alleine auf dem Server:\n') + RES;
  }
  else
  {
    result = string("erf¸llt");
    desc = string('Auf dem Server laufen keine zu ¸berpr¸fenden Dienste.') + RES;
  }
}

set_kb_item(name:"GSHB-12/M4_097/result", value:result);
set_kb_item(name:"GSHB-12/M4_097/desc", value:desc);
set_kb_item(name:"GSHB-12/M4_097/name", value:name);

silence = get_kb_item("GSHB-12/silence");

if (silence){
exit(0);
} else {
  report = 'Ergebnisse zum IT-Grundschutz, 12. Erg‰nzungslieferung:\n\n';
  report = report + name + 'Ergebnis:\t' + result +
           '\nDetails:\t' + desc + '\n\n';
    if ("nicht erf¸llt" >< result || result >< "Fehler"){
    security_hole(port:0, proto: "IT-Grundschutz", data:report);
    } else if (result >< "unvollst‰ndig"){
    security_warning(port:0, proto: "IT-Grundschutz", data:report);
    } else if (result >< "erf¸llt" || result >< "nicht zutreffend"){
    security_note(port:0, proto: "IT-Grundschutz", data:report);
    }
exit(0);
}
