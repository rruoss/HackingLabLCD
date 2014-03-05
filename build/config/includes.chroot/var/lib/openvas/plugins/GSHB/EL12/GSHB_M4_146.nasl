###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_146.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 12. EL, Maﬂnahme 4.146
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
tag_summary = "IT-Grundschutz M4.146: Sicherer Betrieb von Windows Client-Betriebssystemen.

Diese Pr¸fung bezieht sich auf die 12. Erg‰nzungslieferung (12. EL) des IT-
Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

Hinweis:

Vista und Windows 7 bei aktiviertem UAC zur Zeit noch nicht mˆglich.

http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04146.html";

if(description)
{
  script_id(94063);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2011-11-07 13:38:53 +0100 (Mon, 07 Nov 2011)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.146: Sicherer Betrieb von Windows Client-Betriebssystemen");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("IT-Grundschutz M4.146: Sicherer Betrieb von Windows Client-Betriebssystemen.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-12");
  script_mandatory_keys("Compliance/Launch/GSHB-12");
  script_dependencies("GSHB/GSHB_SLAD_SFC_verifyonly.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.146: Sicherer Betrieb von Windows Client-Betriebssystemen\n';

gshbm =  "IT-Grundschutz M4.146: ";

OSVER = get_kb_item("WMI/WMI_OSVER");
OSTYPE = get_kb_item("WMI/WMI_OSTYPE");
OSNAME = get_kb_item("WMI/WMI_OSNAME");
WMIOSLOG = get_kb_item("WMI/WMI_OS/log");
SFCVERIFYONLY = get_kb_item("GSHB/SLAD/SFC");
log = get_kb_item("GSHB/SLAD/SFC/log");

if (WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System."){
  result = string("nicht zutreffend");
  desc = string("Auf dem System l‰uft Samba,\nes ist kein Microsoft Windows System.");
}if (OSVER >< "none"){
  result = string("nicht zutreffend");
  desc = string("Das System wurde nicht als Microsoft Windows System erkannt.");
}else if(OSVER != "none" && (OSVER < '5.0' || ( OSVER == '5.2' && OSNAME >!< 'Microsoft(R) Windows(R) XP Professional x64 Edition') || (OSVER > '5.2' && OSTYPE != 1))){
  result = string("nicht zutreffend");
  desc = string("Das System ist kein Windows Client.");
}else if("Microsoft Windows XP" >< SFCVERIFYONLY){
  result = string("unvollst‰ndig");
  desc = string('Unter Windows 2000 und Windows XP kann dieser Test\nnicht ausgef¸hrt werden');
}else if(SFCVERIFYONLY >< "no ssh"){
  result = string("Fehler");
   desc = string('Beim Testen des Systems wurde festgestellt, dass keine\nSSH Verbindung aufgebaut werden konnte. Das kˆnnte daran\nliegen, dass WinSLAD auf dem Ziel nicht installiert ist.\nWinSLAD wird benˆtigt um diesen Test auszuf¸hren. Dabei wird\nauch der nˆtige SSH-Zugang zum System mit installiert.');
}else if(SFCVERIFYONLY =~ "404 (P|p)lugin not found.*"){
  result = string("Fehler");
  desc = string('Beim Testen des Systems wurde festgestellt, dass das\nnotwendige SFC-Plugin nicht installiert ist.');
}else if("Still running processes" >< SFCVERIFYONLY){
  result = string("unvollst‰ndig");
  desc = string('\nBeim Testen des Systems wurde festgestellt, dass SLAD\nnocht nicht fertig ist.\nBitte wiederholen Sie den\nTest sp‰ter noch einmal.');
}else if("no results" >< SFCVERIFYONLY){
  result = string("Fehler");
  desc = string('Beim Testen des Systems wurde festgestellt, dass SLAD\nkeine Ergebnisse geliefert hat.');
}else if("Sie m¸ssen als Administrator angemeldet sein" >< SFCVERIFYONLY || "You must be an administrator running a console session" >< SFCVERIFYONLY){
  result = string("Fehler");
  desc = string('Sie haben nicht gen¸gend Rechte auf dem System. Das\nProblem taucht in der Regel unter Windows Vista und\nWindows 7 bei aktiviertem UAC auf\n') + SFCVERIFYONLY;



}else if("Der Windows-Ressourcenschutz hat keine Integrit‰tsverletzungen gefunden." >< SFCVERIFYONLY || "Windows Resource Protection did not find any integrity violations." >< SFCVERIFYONLY){
  result = string("erf¸llt");
  desc = string('Der Windows-Ressourcenschutz hat keinen Fehler auf\ndem System festgestellt.\n') + SFCVERIFYONLY;
}else if("Der Windows-Ressourcenschutz hat Integrit‰tsverletzungen festgestellt." >< SFCVERIFYONLY || "Windows Resource Protection found integrity violations." >< SFCVERIFYONLY){
  result = string("nicht erf¸llt");
  desc = string('\nDer Windows-Ressourcenschutz hat Fehler auf dem System\nfestgestellt. Details finden Sie auf dem Zielsystem in\nder Datei CBS.log (windir\\Logs\\CBS\\CBS.log),\nz.B. C:\\Windows\\Logs\\CBS\\CBS.log');
}else{
  result = string("Fehler");
  desc = string('Ein unbekanntes Ergebnis ist aufgetreten:') + SFCVERIFYONLY;
}



set_kb_item(name:"GSHB-12/M4_146/result", value:result);
set_kb_item(name:"GSHB-12/M4_146/desc", value:desc);
set_kb_item(name:"GSHB-12/M4_146/name", value:name);

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
