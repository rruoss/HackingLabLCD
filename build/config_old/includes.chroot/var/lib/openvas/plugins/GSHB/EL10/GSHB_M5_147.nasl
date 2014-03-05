###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M5_147.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 10. EL, Maﬂnahme 5.147
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
tag_summary = "IT-Grundschutz M5.147: Absicherung der Kommunikation mit Verzeichnisdiensten (Win).

  Diese Pr¸fung bezieht sich auf die 10. Erg‰nzungslieferung (10. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
  Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

  http://www.bsi.bund.de/grundschutz/kataloge/m/m05/m05147.html";


if(description)
{
  script_id(95147);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Thu Jan 14 14:29:35 2010 +0100");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M5.147: Absicherung der Kommunikation mit Verzeichnisdiensten (Win)");
  if (! OPENVAS_VERSION)
  {
    desc = "
    Leider setzen Sie einen zu alten OpenVAS Scan-Server ein.
    Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!";
    script_description(desc);
    script_summary("IT-Grundschutz M5.147: Absicherung der Kommunikation mit Verzeichnisdiensten (Win).");
    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
    script_family("IT-Grundschutz-10");
    exit(0);
  }
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("IT-Grundschutz M5.147: Absicherung der Kommunikation mit Verzeichnisdiensten (Win).");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-10");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-10");
  script_dependencies("GSHB/GSHB_WMI_OSInfo.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M5.147: Absicherung der Kommunikation mit Verzeichnisdiensten (Win)\n';

if (! OPENVAS_VERSION)
{
        set_kb_item(name:"GSHB-10/M5_147/result", value:"nicht zutreffend");
        set_kb_item(name:"GSHB-10/M5_147/desc", value:"Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!");
        set_kb_item(name:"GSHB-10/M5_147/name", value:name);
    log_message(port:0, proto: "IT-Grundschutz", data:string("Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!"));  
    exit(0);
}


gshbm =  "IT-Grundschutz M5.147: ";

OSVER = get_kb_item("WMI/WMI_OSVER");
OSTYPE = get_kb_item("WMI/WMI_OSTYPE");
OSNAME = get_kb_item("WMI/WMI_OSNAME");
WMIOSLOG = get_kb_item("WMI/WMI_OS/log");
PORT389 = get_kb_list("Ports/tcp/389");
PORT636 = get_kb_list("Ports/tcp/636");

#foreach port (keys(ports))
#{
#   port = int(port - 'Ports/tcp/');
#   portlist = portlist + port + '|';
#}

if (WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System."){
  result = string("nicht zutreffend");
  desc = string("Auf dem System l‰uft Samba, es ist kein Microsoft System.");
}else if("none" >< OSVER){
  result = string("Fehler");
  if (!log)desc = string("Beim Testen des Systems trat ein Fehler auf, siehe Log Message!");
  if (log)desc = string("Beim Testen des Systems trat ein Fehler auf: " + log);
}else if(OSVER == '5.1' || (OSVER == '5.2' && OSNAME >< 'Microsoft(R) Windows(R) XP Professional x64 Edition') || (OSVER == '6.0' && OSTYPE == 1 ) || (OSVER == '6.1' && OSTYPE == 1 )){
  result = string("nicht zutreffend");
  desc = string("Das System ist kein Server.");
}
else
{
  if (PORT389)
  {
    if (PORT636)
    {
      result = string("erf¸llt");
      desc = string('LDAP ¸ber SSL/TLS ist aktiviert.');
    }
    else
    {
      result = string("nicht erf¸llt");
      desc = string('LDAP ¸ber SSL/TLS ist nicht aktiviert.');
    }
  }
  else
  {
    if (PORT636)
    {
      result = string("erf¸llt");
      desc = string('LDAP ist nur ¸ber SSL/TLS aktiviert.');
    }
    else
    {
      result = string("nicht zutreffen");
      desc = string('LDAP ist auf dem Server nicht installiert.');
    }
  }
}

set_kb_item(name:"GSHB-10/M5_147/result", value:result);
set_kb_item(name:"GSHB-10/M5_147/desc", value:desc);
set_kb_item(name:"GSHB-10/M5_147/name", value:name);

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
