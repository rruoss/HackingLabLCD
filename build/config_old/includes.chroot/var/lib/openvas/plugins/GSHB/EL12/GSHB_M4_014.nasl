###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_014.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 12. EL, Maﬂnahme 4.014
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
tag_summary = "IT-Grundschutz M4.014: Obligatorischer Passwortschutz unter Unix.

Diese Pr¸fung bezieht sich auf die 12. Erg‰nzungslieferung (12. EL) des IT-
Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04014.html";


if(description)
{
  script_id(94025);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2011-11-07 13:38:53 +0100 (Mon, 07 Nov 2011)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.014: Obligatorischer Passwortschutz unter Unix");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("IT-Grundschutz M4.014: Obligatorischer Passwortschutz unter Unix.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-12");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-12");
  script_dependencies("GSHB/GSHB_SSH_passwords.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


name = 'IT-Grundschutz M4.014: Obligatorischer Passwortschutz unter Unix\n';

gshbm =  "IT-Grundschutz M4.014: ";

OSVER = get_kb_item("WMI/WMI_OSVER");
SHADOW = get_kb_item("GSHB/etc_shadow");
NoPWUser = get_kb_item("GSHB/NoPWUser");
PWUser = get_kb_item("GSHB/PWUser");
SunPasswd = get_kb_item("GSHB/SunPasswd");
LOG = get_kb_item("GSHB/etc_shadow/log");


Testdays = "180";
    
if(OSVER >!< "none"){
  OSNAME = get_kb_item("WMI/WMI_OSNAME");
  result = string("nicht zutreffend");
  desc = string('Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nFolgendes System wurde erkannt:\n' + OSNAME);
}else if(SHADOW == "windows") {
    result = string("nicht zutreffend");
    desc = string('Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nDas System scheint ein Windows-System zu sein.');
}else if (LOG){
  result = string("Fehler");
  desc = string('Beim Testen des Systems ist ein Fehler aufgetreten:\n' + LOG);
}else if(PWUser != "none" || NoPWUser!= "none"){
  User = split(PWUser, sep:";", keep:0);
  for(i=0; i<max_index(User); i++){
    val = split(User[i], sep:":", keep:0);
    if (int(val[1]) > int(Testdays)) Failuser += '\nUser: ' + val[0] +", zuletzt ge‰ndert vor " + val[1] + " Tagen";
  }
  if (NoPWUser >!< "none" || Failuser){
    result = string("nicht erf¸llt");
    if (NoPWUser >!< "none") desc = string('Beim Testen des Systems wurde festgestellt, dass\nfolgende Benutzer kein Passwort haben:\n' + NoPWUser);
    if (Failuser) desc += string('\nBeim Testen des Systems wurde festgestellt, dass\nfolgende User ihr Passwort seit ¸ber ' + Testdays + "\nTagen nicht ge‰ndert haben:" + Failuser);
  }else if(SunPasswd >< "noperm"){
    result = string("Fehler");
    desc = string('Beim Testen des Systems wurde festgestellt, dass die\nBerechtigung nicht reicht um "passwd -sa" auszuf¸hren.');
  }else{
      result = string("Fehler");
      desc = string("Beim Testen des Systems trat ein unbekannter Fehler auf.");
  }
}else if (SHADOW == "nopermission" && PWUser == "none" && NoPWUser == "none"){
  result = string("unvollst‰ndig");
  desc = string('Beim Testen des Systems wurde festgestellt, dass der\nTestbenutzer keine Berechtigung hat den Befehl passwd\nauszuf¸hren. Alternativ wurde versucht, die Datei\n/etc/shadow zu lesen. Bitte pr¸fen Sie manuell ob die\nUser der Maﬂnahme M4.014 entsprechen.');
}else if (SHADOW == "noshadow" && PWUser == "none" && NoPWUser == "none"){
  result = string("nicht erf¸llt");
  desc = string('Beim Testen des Systems wurde festgestellt, dass die\nDatei /etc/shadow anscheinend nicht vorhanden ist,\nbzw. nicht genutzt wird.');
}


set_kb_item(name:"GSHB-12/M4_014/result", value:result);
set_kb_item(name:"GSHB-12/M4_014/desc", value:desc);
set_kb_item(name:"GSHB-12/M4_014/name", value:name);

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
