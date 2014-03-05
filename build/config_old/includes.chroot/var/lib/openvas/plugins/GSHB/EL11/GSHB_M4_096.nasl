###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_096.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 11. EL, Maﬂnahme 4.096
#
# Authors:
# Thomas Rotter <T.Rotter@dn-systems.de>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "IT-Grundschutz M4.096: Abschaltung von DNS.

  Diese Pr¸fung bezieht sich auf die 11. Erg‰nzungslieferung (11. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
  Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

  http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04096.html";


if(description)
{
  script_id(894096);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Mon Jun 07 13:23:53 2010 +0200");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.096: Abschaltung von DNS");
  if (! OPENVAS_VERSION)
  {
    desc = "
    Leider setzen Sie einen zu alten OpenVAS Scan-Server ein.
    Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!";
    script_description(desc);
    script_summary("IT-Grundschutz M4.096: Abschaltung von DNS.");
    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
    script_family("IT-Grundschutz-11");
    exit(0);
  }
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("IT-Grundschutz M4.096: Abschaltung von DNS.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-11");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-11");
  script_dependencies("GSHB/GSHB_SSH_dns.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


name = 'IT-Grundschutz M4.096: Abschaltung von DNS\n';

if (! OPENVAS_VERSION)
{
        set_kb_item(name:"GSHB-11/M4_096/result", value:"nicht zutreffend");
        set_kb_item(name:"GSHB-11/M4_096/desc", value:"Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!");
        set_kb_item(name:"GSHB-11/M4_096/name", value:name);
    log_message(port:0, proto: "IT-Grundschutz", data:string("Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!"));  
    exit(0);
}


gshbm =  "IT-Grundschutz M4.096: ";


OSNAME = get_kb_item("WMI/WMI_OSNAME");

VAL1 = get_kb_item("GSHB/DNSTEST/VAL1");
VAL2 = get_kb_item("GSHB/DNSTEST/VAL2");
VAL3 = get_kb_item("GSHB/DNSTEST/VAL3");
VAL4 = get_kb_item("GSHB/DNSTEST/VAL4");
VAL5 = get_kb_item("GSHB/DNSTEST/VAL5");
log = get_kb_item("GSHB/DNSTEST/log");

www = get_kb_list("Services/www");

if (www){
  Lst = split(www, sep:",", keep:0);
  for(i=0; i<max_index(Lst); i++){
    val = split(Lst[i], sep:":", keep:0);
    if (val[1] == " 80" || val[1] == " 443" || val[1] == " 8080" || val[1] == " 8008"|| val[1] == " 8088")ports += val[1] + ", ";
  }
  if (ports){
    ports = ports - "[";
    ports = ports - "]";
  }
}


if (VAL1 == "error" && OSNAME == "none"){
  result = string("Fehler");
  if (!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
  if (log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
}else if (!ports){
  result = string("nicht zutreffend");
  desc = string('Das System scheint kein Internetserver zu sein. Es\nwurden bei der ‹berpr¸fung nur die Ports 80, 443,\n8008, 8080 und 8088 beachtet.'); 
}else if (OSNAME != "none"){
  result = string("nicht zutreffend");
   desc = string('Folgendes System wurde erkannt:\n' + OSNAME);
}else if (VAL1 == "TRUE" || VAL2 == "TRUE" || VAL3 == "TRUE" || VAL4 == "TRUE" || VAL5 == "TRUE"){
  result = string("nicht erf¸llt");
  desc = string('Das System scheint ein Internetserver zu sein.\nEntgegen der Empfehlung aus Maﬂnahme 4.096, l‰uft es\nmit aktiviertem DNS.'); 
}else{
  result = string("erf¸llt");
  desc = string('Das System scheint ein Internetserver zu sein. Wie in\nder Maﬂnahme 4.096 Empfohlen, l‰uft es ohne\naktiviertem DNS.'); 
}

if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler\nauf bzw. es konnte kein Ergebnis ermittelt werden.'); 
}


set_kb_item(name:"GSHB-11/M4_096/result", value:result);
set_kb_item(name:"GSHB-11/M4_096/desc", value:desc);
set_kb_item(name:"GSHB-11/M4_096/name", value:name);

silence = get_kb_item("GSHB-11/silence");

if (silence){
exit(0);
} else {
  report = 'Ergebnisse zum IT-Grundschutz, 11. Erg‰nzungslieferung:\n\n';
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
