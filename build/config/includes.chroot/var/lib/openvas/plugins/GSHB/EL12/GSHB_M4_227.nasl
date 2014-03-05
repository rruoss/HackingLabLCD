###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_227.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 12. EL, Maﬂnahme 4.227
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
tag_summary = "IT-Grundschutz M4.227: Einsatz eines lokalen NTP-Servers zur Zeitsynchronisation (Win).

Diese Pr¸fung bezieht sich auf die 12. Erg‰nzungslieferung (12. EL) des IT-
Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04227.html";


if(description)
{
  script_id(94066);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2011-11-07 13:38:53 +0100 (Mon, 07 Nov 2011)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.227: Einsatz eines lokalen NTP-Servers zur Zeitsynchronisation (Win)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("IT-Grundschutz M4.227: Einsatz eines lokalen NTP-Servers zur Zeitsynchronisation (Win).");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-12");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-12");
  script_dependencies("GSHB/GSHB_WMI_NtpServer.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  script_require_keys("WMI/NtpServer", "WMI/WMI_WindowsDomain");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.227: Einsatz eines lokalen NTP-Servers zur Zeitsynchronisation (Win)\n';

gshbm =  "IT-Grundschutz M4.227: ";
WMIOSLOG = get_kb_item("WMI/WMI_OS/log");
ntpserver = get_kb_item("WMI/NtpServer");
ntpserver = tolower(ntpserver);
domain = get_kb_item("WMI/WMI_WindowsDomain");
domain = tolower(domain);
log = get_kb_item("WMI/NtpServer/log");

if (ntpserver >!< "none" && ntpserver >!< "error") ntpserver = split(ntpserver, sep:",", keep:0);

if (WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System."){
  result = string("nicht zutreffend");
  desc = string("Auf dem System l‰uft Samba,\nes ist kein Microsoft Windows System.");
}else if("error" >< ntpserver){
  result = string("Fehler");
  if (!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
  if (log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
}else if("none" >< ntpserver){
  result = string("nicht zutreffend");
  desc = string("Auf dem System wurde kein Eintrag f¸r einen\nNTP-Server gefunden");
}else if(domain >< ntpserver[0]){
  result = string("erf¸llt");
  desc = string("Auf dem System wurde ein lokaler NTP-Server\nhinterlegt: " + ntpserver[0]);
}else if(domain >!< ntpserver[0]){
  result = string("nicht erf¸llt");
  desc = string("Auf dem System wurde ein externer NTP-Server\nhinterlegt: " + ntpserver[0]);
}

set_kb_item(name:"GSHB-12/M4_227/result", value:result);
set_kb_item(name:"GSHB-12/M4_227/desc", value:desc);
set_kb_item(name:"GSHB-12/M4_227/name", value:name);

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
