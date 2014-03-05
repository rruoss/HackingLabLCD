###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_001.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 12. EL, Ma�nahme 4.001
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
tag_summary = "IT-Grundschutz M4.001: Passwortschutz f�r IT-Systeme.

Diese Pr�fung bezieht sich auf die 12. Erg�nzungslieferung (12. EL) des IT-
Grundschutz. Die detaillierte Beschreibung zu dieser Ma�nahme findet sich unter
nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
die aktuellste Erg�nzungslieferung bezieht. Titel und Inhalt k�nnen sich bei einer
Aktualisierung �ndern, allerdings nicht die Kernthematik.

Hinweis:

Ein Test von Vista und Windows 7 ist bei aktiviertem UAC, zur Zeit noch nicht m�glich.

http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04001.html";

if(description)
{
  script_id(94006);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2011-11-07 13:38:53 +0100 (Mon, 07 Nov 2011)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.001: Passwortschutz f�r IT-Systeme");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("IT-Grundschutz M4.001: Passwortschutz f�r IT-Systeme.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-12");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-12");
  script_dependencies("GSHB/GSHB_SLAD_fastjohn.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.001: Passwortschutz f�r IT-Systeme\n';

gshbm =  "IT-Grundschutz M4.001: ";

fastjohn = get_kb_item("GSHB/SLAD/FASTJOHN");
log = get_kb_item("GSHB/SLAD/FASTJOHN/log");
OSVER = get_kb_item("WMI/WMI_OSVER");
OSTYPE = get_kb_item("WMI/WMI_OSTYPE");
OSNAME = get_kb_item("WMI/WMI_OSNAME");
OSArchitecture = get_kb_item("WMI/WMI_OSArchitecture");

if(OSVER >= '6.0' && OSTYPE == 1){
  result = string("unvollst�ndig");
  desc = string('Folgendes System wurde erkannt:\n' + OSNAME + '\nDieses System kann nicht getestet werden, da der\nWinslad Plugin "John the Ripper", durch das Windows\neigene UAC am starten gehindert wird. Hierbei handelt\nes sich um ein generelles Problem seit Einf�hrung vom\nUser Account Control (UAC) in Windows.');
}else if(fastjohn >< "no ssh"){
  result = string("Fehler");
   desc = string('Beim Testen des Systems wurde festgestellt, dass keine\nSSH Verbindung aufgebaut werden konnte. Das k�nnte daran\nliegen, dass WinSLAD auf dem Ziel nicht installiert ist.\nWinSLAD wird ben�tigt um diesen Test auszuf�hren. Dabei wird\nauch der n�tige SSH-Zugang zum System mit installiert.');
}else if(fastjohn >< "noslad"){
  result = string("Fehler");
  desc = string("SLAD konnte nicht gestartet werden.\nWahrscheinlich ist es nicht installiert.");
}else if(fastjohn >< "no results"){
  result = string("Fehler");
  desc = string("Beim Testen des Systems hat SLAD kein R�ckmeldung\ngegeben. Wahrscheinlich ist es nicht installiert.");
}else if("Still running processes" >< fastjohn){
  result = string("unvollst�ndig");
  desc = string('Beim Testen des Systems wurde festgestellt,\ndass SLAD noch nicht fertig ist.\nBitte wiederholen Sie den Test sp�ter noch einmal.');
}else{
    Lst = split(fastjohn, sep:"|", keep:0);
    for(i=0; i<max_index(Lst); i++){
      if ("NOPW=" >< Lst[i]){
        nopwuser = Lst[i] - "NOPW=";
      }  
      else if("WEAK=" >< Lst[i]){
        weakuser = Lst[i] - "WEAK=";
      }
    }
  if(nopwuser || weakuser){
    result = string("nicht erf�llt");
    desc = string('Folgende Benutzer entsprechen nicht den Anforderungen\ndes IT-Grundschutz-Katalogs:');
    if (nopwuser) desc += '\nKeine Passwort: ' + nopwuser;
    if (weakuser) desc += '\nUnsicheres Passwort: ' + weakuser;    
  }else{
    result = string("erf�llt");
    desc = string("Es konnte kein Benutzer ohne Passwort erkannt werden.\nSie scheinen den Anforderungen des IT-Grundschutz-\nKatalogs zu entsprechen.");
  }
}

set_kb_item(name:"GSHB-12/M4_001/result", value:result);
set_kb_item(name:"GSHB-12/M4_001/desc", value:desc);
set_kb_item(name:"GSHB-12/M4_001/name", value:name);

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