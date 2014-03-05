###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_020.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 11. EL, Maﬂnahme 4.020
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
tag_summary = "IT-Grundschutz M4.020: Restriktive Attributvergabe bei Unix-Benutzerdateien und -verzeichnissen.

  Diese Pr¸fung bezieht sich auf die 11. Erg‰nzungslieferung (11. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
  Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

  http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04020.html";

if(description)
{
  script_id(894020);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Fri Mar 12 14:41:17 2010 +0100");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.020: Restriktive Attributvergabe bei Unix-Benutzerdateien und -verzeichnissen");
  
  if (! OPENVAS_VERSION)
  {
    desc = "Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!";
    script_description(desc);
    script_summary("IT-Grundschutz M4.020: Restriktive Attributvergabe bei Unix-Benutzerdateien und -verzeichnissen.");
    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
    script_family("IT-Grundschutz-11");
    exit(0);
  }
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("IT-Grundschutz M4.020: Restriktive Attributvergabe bei Unix-Benutzerdateien und -verzeichnissen.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-11");
  script_mandatory_keys("Compliance/Launch/GSHB-11");
  script_dependencies("GSHB/GSHB_SSH_umask.nasl", "GSHB/GSHB_SSH_setuid.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.020: Restriktive Attributvergabe bei Unix-Benutzerdateien und -verzeichnissen\n';



if (! OPENVAS_VERSION)
  {
        set_kb_item(name:"GSHB-11/M4_020/result", value:"nicht zutreffend");
        set_kb_item(name:"GSHB-11/M4_020/desc", value:"Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!");
        set_kb_item(name:"GSHB-11/M4_020/name", value:name);
    log_message(port:0, proto: "IT-Grundschutz", data:string("Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!"));  
    exit(0);
}

gshbm =  "IT-Grundschutz M4.020: ";

umask = get_kb_item("GSHB/umask");
umasklog = get_kb_item("GSHB/umask/log");
OSNAME = get_kb_item("WMI/WMI_OSNAME");
WMIOSLOG = get_kb_item("WMI/WMI_OS/log");
setuid = get_kb_item("GSHB/setuid/home");
setuidlog = get_kb_item("GSHB/setuid/log");
tempsticky = get_kb_item("GSHB/tempsticky");

if(OSNAME >!< "none"){
  result = string("nicht zutreffend");
  desc = string('Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nFolgendes System wurde erkannt:\n' + OSNAME);
}else if(umask >< "error"){
  result = string("Fehler");
  if (!umasklog)desc = string('Beim Testen des Systems trat ein unbekannter\nFehler auf.');
  if (umasklog)desc = string('Beim Testen des Systems trat ein Fehler auf:\n' + umasklog);
}else if(umask == "windows") {
    result = string("nicht zutreffend");
    desc = string('Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nDas System scheint ein Windows-System zu sein.');
}else if(umask >< "none" && setuid >< "none" && (tempsticky == "true" || tempsticky == "notmp" )){
  result = string("erf¸llt");
  desc = string('Es konnten keine fehlerhaften umask-Eintr‰ge und\nDateien mit setuid-Bit unter /home/* gefunden werden.');
}else if(umask >!< "none" || setuid >!< "none" || tempsticky == "false"){
  result = string("nicht erf¸llt");
  if(umask >!< "none") desc = string('Folgende fehlerhaften umask-Eintr‰ge wurden gefunden:\n' + umask);
  if(setuid >!< "none") desc += string('Folgende Dateien mit setuid-Bit wurden gefunden:\n' + setuid);
  if(tempsticky == "false") desc += string('F¸r das Verzeichnis /tmp wurde das sticky-Bit\nnicht gesetzt.');
}

set_kb_item(name:"GSHB-11/M4_020/result", value:result);
set_kb_item(name:"GSHB-11/M4_020/desc", value:desc);
set_kb_item(name:"GSHB-11/M4_020/name", value:name);

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
