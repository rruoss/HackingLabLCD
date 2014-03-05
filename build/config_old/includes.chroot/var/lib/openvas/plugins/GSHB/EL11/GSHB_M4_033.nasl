###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_033.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 11. EL, Ma�nahme 4.033
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
tag_summary = "IT-Grundschutz M4.033: Einsatz eines Viren-Suchprogramms bei Datentr�geraustausch und Daten�bertragung (Win).

  Diese Pr�fung bezieht sich auf die 11. Erg�nzungslieferung (11. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Ma�nahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Erg�nzungslieferung bezieht. Titel und Inhalt k�nnen sich bei einer
  Aktualisierung �ndern, allerdings nicht die Kernthematik.

  http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04033.html";


if(description)
{
  script_id(894033);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Thu Jan 14 14:29:35 2010 +0100");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.033: Einsatz eines Viren-Suchprogramms bei Datentr�geraustausch und Daten�bertragung (Win)");
  if (!OPENVAS_VERSION)
  {
    desc = "
    Leider setzen Sie einen zu alten OpenVAS Scan-Server ein.
    Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!";
    script_description(desc);
    script_summary("IT-Grundschutz M4.003: Regelmiger Einsatz eines Anti-Viren-Programms(Win).");
    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
    script_family("IT-Grundschutz-11");
    exit(0);
  }
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("IT-Grundschutz M4.033: Einsatz eines Viren-Suchprogramms bei Datentr�geraustausch und Daten�bertragung (Win).");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-11");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-11");
  script_dependencies("GSHB/GSHB_WMI_Antivir.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  script_require_keys("WMI/Antivir");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.033: Einsatz eines Viren-Suchprogramms bei Datentr�geraustausch und Daten�bertragung (Win)\n';

  if (!OPENVAS_VERSION)
{
        set_kb_item(name:"GSHB-11/M4_033/result", value:"nicht zutreffend");
        set_kb_item(name:"GSHB-11/M4_033/desc", value:"Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!");
        set_kb_item(name:"GSHB-11/M4_033/name", value:name);
    log_message(port:0, proto: "IT-Grundschutz", data:string("Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!"));  
    exit(0);
}



gshbm =  "IT-Grundschutz M4.033: ";

WMIOSLOG = get_kb_item("WMI/WMI_OS/log");
Antivir = get_kb_item("WMI/Antivir");
AntivirName = get_kb_item("WMI/Antivir/Name");
#AntivirName = split(AntivirName, sep:"|", keep:0);
AntivirUptoDate = get_kb_item("WMI/Antivir/UptoDate");
if (AntivirUptoDate >!< "None") AntivirUptoDate = split(AntivirUptoDate, sep:"|", keep:0);
AntivirEnable = get_kb_item("WMI/Antivir/Enable");
if (AntivirEnable >!< "None") AntivirEnable = split(AntivirEnable, sep:"|", keep:0);
AntivirState = get_kb_item("WMI/Antivir/State");
if (AntivirState >!< "None") AntivirState = split(AntivirState, sep:"|", keep:0);

log = get_kb_item("WMI/Antivir/log");

if (WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System."){
  result = string("nicht zutreffend");
  desc = string("Auf dem System l�uft Samba, dieser Test l�uft nur auf\nMicrosoft Windows Systemen.");
}else if(Antivir >< "error"){
  result = string("Fehler");
  if (!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
  if (log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
}else if(Antivir >< "Server"){
  result = string("nicht zutreffend");
  desc = string("Das System ist ein Server und kann nicht\ngetestet werden.");
}else if(Antivir >< "None"){
  result = string("nicht erf�llt");
  desc = string("Auf dem System wurde kein Antivirenprogramm gefunden.");
}else if(Antivir >< "Server"){
  result = string("nicht zutreffend");
  desc = string("Das System ist ein Server und kann nicht\ngetestet werden.");
}else if(Antivir >< "Windows XP <= SP1"){
  result = string("nicht zutreffend");
  desc = string("Das System ist ein Windows XP System kleiner oder\ngleich Service Pack 1 und kann nicht getestet werden.");
}else if(AntivirName >!< "None" && AntivirState >< "None"){
    if ("True" >< AntivirEnable[2] && "True" >< AntivirUptoDate[2]){
      result = string("erf�llt");
      desc = string("Das System hat einen Virenscanner installiert, welcher\nl�uft und aktuell ist.");
    }else if ("True" >< AntivirEnable[2] && "False" >< AntivirUptoDate[2]){
      result = string("nicht erf�llt");
      desc = string("Das System hat einen Virenscanner installiert, welcher\nl�uft aber veraltet ist.");
    }else if ("False" >< AntivirEnable[2] && "True" >< AntivirUptoDate[2]){
      result = string("nicht erf�llt");
      desc = string("Das System hat einen Virenscanner installiert, welcher\nausgeschaltet aber aktuell ist.");
    }else if ("False" >< AntivirEnable[2] && "False" >< AntivirUptoDate[2]){
      result = string("nicht erf�llt");
      desc = string("Das System hat einen Virenscanner installiert, welcher\nausgeschaltet und veraltet ist.");
    }
}else if(AntivirName >!< "None" && AntivirState >!< "None"){
    if ("266240" >< AntivirState[2]){
      result = string("erf�llt");
      desc = string("Das System hat einen Virenscanner installiert, welcher\nl�uft und aktuell ist.");
    }else if ("266256" >< AntivirState[2]){
      result = string("nicht erf�llt");
      desc = string("Das System hat einen Virenscanner installiert, welcher\nl�uft aber veraltet ist.");
    }else if ("262144"  >< AntivirState[2] || "270336" >< AntivirState[2]){
      result = string("nicht erf�llt");
      desc = string("Das System hat einen Virenscanner installiert, welcher\nausgeschaltet aber aktuell ist.");
    }else if ("262160"  >< AntivirState[2] || "270352" >< AntivirState[2]){
      result = string("nicht erf�llt");
      desc = string("Das System hat einen Virenscanner installiert, welcher\nausgeschaltet und veraltet ist.");
    }
}
set_kb_item(name:"GSHB-11/M4_033/result", value:result);
set_kb_item(name:"GSHB-11/M4_033/desc", value:desc);
set_kb_item(name:"GSHB-11/M4_033/name", value:name);

silence = get_kb_item("GSHB-11/silence");

if (silence){
exit(0);
} else {
  report = 'Ergebnisse zum IT-Grundschutz, 11. Erg�nzungslieferung:\n\n';
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

