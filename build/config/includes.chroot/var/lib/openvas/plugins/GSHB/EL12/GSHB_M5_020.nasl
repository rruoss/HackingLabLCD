###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M5_020.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 12. EL, Ma�nahme 5.020
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
tag_summary = "IT-Grundschutz M5.020: Einsatz der Sicherheitsmechanismen von rlogin, rsh und rcp.

Diese Pr�fung bezieht sich auf die 12. Erg�nzungslieferung (12. EL) des IT-
Grundschutz. Die detaillierte Beschreibung zu dieser Ma�nahme findet sich unter
nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
die aktuellste Erg�nzungslieferung bezieht. Titel und Inhalt k�nnen sich bei einer
Aktualisierung �ndern, allerdings nicht die Kernthematik.

http://www.bsi.bund.de/grundschutz/kataloge/m/m05/m05020.html";

if(description)
{
  script_id(95006);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2011-11-07 13:38:53 +0100 (Mon, 07 Nov 2011)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M5.020: Einsatz der Sicherheitsmechanismen von rlogin, rsh und rcp");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("IT-Grundschutz M5.020: Einsatz der Sicherheitsmechanismen von rlogin, rsh und rcp.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-12");
  script_mandatory_keys("Compliance/Launch/GSHB-12");
  script_dependencies ("GSHB/GSHB_SSH_r-tools.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M5.020: Einsatz der Sicherheitsmechanismen von rlogin, rsh und rcp\n';

gshbm =  "IT-Grundschutz M5.020: ";

OSNAME = get_kb_item("WMI/WMI_OSNAME");

rhosts = get_kb_item("GSHB/R-TOOL/rhosts");
hostsequiv = get_kb_item("GSHB/R-TOOL/hostsequiv");
lshostsequiv = get_kb_item("GSHB/R-TOOL/lshostsequiv");
inetdconf = get_kb_item("GSHB/R-TOOL/inetdconf");
rlogind = get_kb_item("GSHB/R-TOOL/rlogind");
rshd = get_kb_item("GSHB/R-TOOL/rshd");
log = get_kb_item("GSHB/R-TOOL/log");

if(OSNAME >!< "none"){
  result = string("nicht zutreffend");
  desc = string('Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nFolgendes System wurde erkannt:\n' + OSNAME);
}else if(rhosts == "windows") {
    result = string("nicht zutreffend");
    desc = string('Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nDas System scheint ein Windows-System zu sein.');
}else if(rhosts == "error"){
  result = string("Fehler");
  if(!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
  if(log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
}else if(rhosts == "not found" && (hostsequiv == "none" || hostsequiv == "noentry") && (lshostsequiv == "none" || lshostsequiv =~ ".......---...root root.*") && (inetdconf == "noentry" || inetdconf == "none") && rlogind == "not found" && rshd == "not found"){
  result = string("erf�llt");
  desc = string("Das System entspricht der Ma�nahme 5.020.");
}else if (rhosts != "not found" || (hostsequiv != "noentry" && hostsequiv != "none") || (lshostsequiv != "none" && lshostsequiv !~ ".......---...root root.*")){
  result = string("nicht erf�llt");
  desc = string('Es muss sichergestellt werden, dass die Dateien\n$HOME/.rhosts und /etc/hosts.equiv nicht vorhanden sind oder\ndass sie leer sind und der Benutzer keine Zugriffsrechte auf\nsie hat.');
   if (rhosts != "not found") desc += string('\nFolgende .rhost Dateien wurden gefunden:\n' + rhosts);
   if (hostsequiv != "none"){
     val = split(lshostsequiv, sep:" ", keep:0);   
     desc += string('\nFolgende Zugriffsrechte gelten f�r -/etc/hosts.equiv- :\n' + val[0] + " " + val[2] + " "+ val[3]);
   }
   if (hostsequiv != "noentry" && hostsequiv != "none")desc += string('\nFolgende Eintr�ge wurden in  -/etc/hosts.equiv- gefunden:\n' + hostsequiv);
   
   if ("+" >< hostsequiv) desc += string('\nSollte die Benutzung der Datei -/etc/hosts.equiv- unumg�nglich\nsein, muss sichergestellt sein, dass kein Eintrag + vorhanden\nist, da hierdurch jeder Rechner vertrauensw�rdig w�rde.');
   
   if (rlogind != "not found" || rshd != "not found"){
     desc += string('\nEs sollte verhindert werden, dass die Daemons rlogind und rshd\ngestartet werden k�nnen. (siehe hierzu die Datei\n/etc/inetd.conf und Ma�nahme M 5.16)');
     if (inetdconf != "none" && inetdconf != "noentry")desc += string('\nFolgende Eintr�ge stehen in Ihrer -/etc/inetd.conf-:\n' + inetdconf);

     else desc += string('\nIhre -/etc/inetd.conf- ist leer.');
   }
}

if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler auf\nbzw. es konnte kein Ergebnis ermittelt werden.'); 
}

set_kb_item(name:"GSHB-12/M5_020/result", value:result);
set_kb_item(name:"GSHB-12/M5_020/desc", value:desc);
set_kb_item(name:"GSHB-12/M5_020/name", value:name);

silence = get_kb_item("GSHB-12/silence");

if (silence){
exit(0);
} else {
  report = 'Ergebnisse zum IT-Grundschutz, 12. Erg�nzungslieferung:\n\n';
  report = report + name + 'Ergebnis:\t' + result +
           '\nDetails:\t' + desc + '\n\n';
    if ("nicht erf�llt" >< result || result >< "Fehler"){
    security_hole(port:0, proto: "IT-Grundschutz", data:report);
    } else if (result >< "unvollst�ndig"){
    security_warning(port:0, proto: "IT-Grundschutz", data:report);
    } else if (result >< "erf�llt" || result >< "nicht zutreffend"){
    security_note(port:0, proto: "IT-Grundschutz", data:report);
    }
exit(0);
}
