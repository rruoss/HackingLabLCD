###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_284.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 10. EL, Maﬂnahme 4.284
#
# Authors:
# Thomas Rotter <T.Rotter@dn-systems.de>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "IT-Grundschutz M4.284: Umgang mit Diensten unter Windows Server 2003 (Win).

  Diese Pr¸fung bezieht sich auf die 10. Erg‰nzungslieferung (10. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
  Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

  http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04284.html";


if(description)
{
  script_id(94284);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Thu Jan 14 14:29:35 2010 +0100");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.284: Umgang mit Diensten unter Windows Server 2003 (Win)");
  if (! OPENVAS_VERSION)
  {
    desc = "
    Leider setzen Sie einen zu alten OpenVAS Scan-Server ein.
    Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!";
    script_description(desc);
    script_summary("IT-Grundschutz M4.284: Umgang mit Diensten unter Windows Server 2003 (Win).");
    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
    script_family("IT-Grundschutz-10");
    exit(0);
  }
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("IT-Grundschutz M4.284: Umgang mit Diensten unter Windows Server 2003 (Win).");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-10");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-10");
  script_dependencies("GSHB/GSHB_WMI_list_Services.nasl", "GSHB/GSHB_WMI_get_AdminUsers.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  script_require_keys("WMI/nonSystemServices", "WMI/LocalWindowsAdminUsers", "WMI/WMI_OSVER","WMI/WMI_OSNAME");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.284: Umgang mit Diensten unter Windows Server 2003 (Win)\n';

if (! OPENVAS_VERSION)
{
        set_kb_item(name:"GSHB-10/M4_284/result", value:"nicht zutreffend");
        set_kb_item(name:"GSHB-10/M4_284/desc", value:"Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!");
        set_kb_item(name:"GSHB-10/M4_284/name", value:name);
    log_message(port:0, proto: "IT-Grundschutz", data:string("Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!"));  
    exit(0);
}


gshbm =  "IT-Grundschutz M4.284: ";
services = get_kb_item("WMI/nonSystemServices");
LocalAdminUsers = get_kb_item("WMI/LocalWindowsAdminUsers");
OSVER = get_kb_item("WMI/WMI_OSVER");
OSNAME = get_kb_item("WMI/WMI_OSNAME");
WMIOSLOG = get_kb_item("WMI/WMI_OS/log");
log = get_kb_item("WMI/LocalWindowsAdminUsers/log");

if ("Name|StartName|State" >< services) services = split(services, sep:'\n', keep:0);
if (LocalAdminUsers >!< "None" && LocalAdminUsers >!< "error") LocalAdminUsers = split(LocalAdminUsers, sep:'|', keep:0);

if (WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System."){
  result = string("nicht zutreffend");
  desc = string("Auf dem System l‰uft Samba, es ist kein Microsoft System.");
}else if("error" >< services){
  result = string("Fehler");
  if (!log) desc = string("Beim Testen des Systems trat ein Fehler auf, siehe Log Message!");
  if (log) desc = string("Beim Testen des Systems trat ein Fehler auf: " + log);
}else if("None" >< services){
  result = string("erf¸llt");
  desc = string("Auf dem System laufen alle Dienste gem‰ﬂ Maﬂnahme M4.284.");
}else if(OSVER != '5.2' || OSNAME >< 'Microsoft(R) Windows(R) XP Professional x64 Edition'){
  result = string("nicht zutreffend");
  desc = string("Das System ist kein Windows 2003 Server.");
}else if("Name|StartName|State" >< services[0]){
    for(i=1; i<max_index(services); i++)
    {
       if("Name|StartName|State" >< services[i]){
          continue;
       }
       svinf = split(services[i], sep:"|", keep:0);
       if(svinf !=NULL)
       {
         svinf[1] = tolower(svinf[1]);
         if ('@' >< svinf[1] || (svinf[1] !~ "[.]\\.*" && svinf[1] =~ "[a-zA-Z0-9‰ƒˆ÷¸‹ﬂ-]{2,}\\.*"))
         {
         result = result + string("erf¸llt ");
         domservices = domservices + "Dienstname: " + svinf[0] + ', Useraccount: ' + svinf[1] + ', Dienststatus: ' + svinf[2] + ';';
         domdesc = string("Auf dem System laufen einige Dienste unter Dom‰nenaccounts. Bitte pr¸fen Sie folgende Dienste:" + '\n');
         }

         else
         {
           for(u=0; u<max_index(LocalAdminUsers); u++)
             {
                 if(LocalAdminUsers[u] >< svinf[1])
                 {
                     result = result + string("nicht erf¸llt ");
                     servicesdesc = servicesdesc + "Dienstname: " + svinf[0] + ', Useraccount: ' + svinf[1] + ', Dienststatus: ' + svinf[2] + ';';
                 }
                 else
                 {
                     result = result + string("erf¸llt ");
                 }

              }
          }

       }
 }

  if ("nicht" >< result) result = string("nicht erf¸llt");
  else result = string("erf¸llt");
  if (servicesdesc) desc = string("Folgende Dienste entsprechen nicht der Maﬂnahme M4.284: " + '\n') + servicesdesc + domdesc + domservices;
  else if (domservices) desc = domdesc + domservices;
  else if(!servicesdesc && !domservices) desc = string("Auf dem System laufen alle Dienste gem‰ﬂ Maﬂnahme M4.284");
}

set_kb_item(name:"GSHB-10/M4_284/result", value:result);
set_kb_item(name:"GSHB-10/M4_284/desc", value:desc);
set_kb_item(name:"GSHB-10/M4_284/name", value:name);


silence = get_kb_item("GSHB-10/silence");

if (silence){
exit(0);
} else {
  report = 'Ergebnisse zum IT-Grundschutz, 10. Erg‰nzungslieferung:\n\n';
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
