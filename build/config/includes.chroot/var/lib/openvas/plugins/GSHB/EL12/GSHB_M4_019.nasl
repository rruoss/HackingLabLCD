###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_019.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 12. EL, Maﬂnahme 4.019
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
tag_summary = "IT-Grundschutz M4.019: Restriktive Attributvergabe bei Unix-Systemdateien und -verzeichnissen.

Diese Pr¸fung bezieht sich auf die 12. Erg‰nzungslieferung (12. EL) des IT-
Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04019.html";

if(description)
{
  script_id(94031);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2011-11-07 13:38:53 +0100 (Mon, 07 Nov 2011)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.019: Restriktive Attributvergabe bei Unix-Systemdateien und -verzeichnissen");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("IT-Grundschutz M4.019: Restriktive Attributvergabe bei Unix-Systemdateien und -verzeichnissen.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-12");
  script_mandatory_keys("Compliance/Launch/GSHB-12");
  script_dependencies("GSHB/GSHB_SSH_umask.nasl", "GSHB/GSHB_SSH_setuid.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.019: Restriktive Attributvergabe bei Unix-Systemdateien und -verzeichnissen\n';

gshbm =  "IT-Grundschutz M4.019: ";

umask = get_kb_item("GSHB/umask");
umasklog = get_kb_item("GSHB/umask/log");
OSNAME = get_kb_item("WMI/WMI_OSNAME");
setuid = get_kb_item("GSHB/setuid/root");
setuidlog = get_kb_item("GSHB/setuid/log");
tempsticky = get_kb_item("GSHB/tempsticky");

if(OSNAME >!< "none"){
  result = string("nicht zutreffend");
  desc = string('Folgendes System wurde erkannt:\n' + OSNAME);
}else if(umask >< "error"){
  result = string("Fehler");
  if (!umasklog)desc = string('Beim Testen des Systems trat ein\nunbekannter Fehler auf.');
  if (umasklog)desc = string('Beim Testen des Systems trat ein Fehler auf:\n' + umasklog);
}else if(umask == "windows") {
    result = string("nicht zutreffend");
    desc = string('Das System scheint ein Windows-System zu sein.');
}else if(umask >< "none" && setuid >< "none" && (tempsticky == "true" || tempsticky == "notmp" )){
  result = string("erf¸llt");
  desc = string('Es konnten keine Fehlerhaften umask Eintr‰ge und\nDateien mit setuid-Bit unter /* gefunden werden.');
}else if(umask >!< "none" || setuid >!< "none" || tempsticky == "false"){
  result = string("nicht erf¸llt");
  if(umask >!< "none") desc = string('Folgende Fehlerhaften umask Eintr‰ge wurden gefunden:\n' + umask);
  if(setuid >!< "none") desc += string('Folgende Dateien mit setuid-Bit wurden gefunden:\n' + setuid);
  if(tempsticky == "false") desc += string('F¸r das Verzeichnis /tmp wurde das sticky-Bit\nnicht gesetzt.');
}

set_kb_item(name:"GSHB-12/M4_019/result", value:result);
set_kb_item(name:"GSHB-12/M4_019/desc", value:desc);
set_kb_item(name:"GSHB-12/M4_019/name", value:name);

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
