##############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_325.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 12. EL, Ma�nahme 4.325
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
tag_summary = "IT-Grundschutz M4.325: L�schen von Auslagerungsdateien

Diese Pr�fung bezieht sich auf die 12. Erg�nzungslieferung (12. EL) des IT-
Grundschutz. Die detaillierte Beschreibung zu dieser Ma�nahme findet sich unter
nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
die aktuellste Erg�nzungslieferung bezieht. Titel und Inhalt k�nnen sich bei einer
Aktualisierung �ndern, allerdings nicht die Kernthematik.

http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04325.html";


if(description)
{
  script_id(94082);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2011-11-07 13:38:53 +0100 (Mon, 07 Nov 2011)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.325: L�schen von Auslagerungsdateien");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("IT-Grundschutz M4.325: L�schen von Auslagerungsdateien");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-12");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-12");
  script_dependencies("GSHB/GSHB_WMI_PolSecSet.nasl", "GSHB/GSHB_WMI_OSInfo.nasl", "GSHB/GSHB_SSH_cryptsetup_swap.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.325: L�schen von Auslagerungsdateien\n';

OSNAME = get_kb_item("WMI/WMI_OSNAME");
PAGEFILE = get_kb_item("WMI/cps/ClearPageFileAtShutdown");
CPSGENERAL = get_kb_item("WMI/cps/GENERAL");
wmilog = get_kb_item("WMI/cps/GENERAL/log");
WMIOSLOG = get_kb_item("WMI/WMI_OS/log");

cryptsetupinst = get_kb_item("GSHB/cryptsetup/inst");
cryptsetupfstab = get_kb_item("GSHB/cryptsetup/fstab");
sshlog = get_kb_item("GSHB/cryptsetup/log");

if(OSNAME >!< "none"){
  if(CPSGENERAL == "error"){
    result = string("Fehler");
    if (!wmilog) desc = string("Beim Testen des Systems trat ein Fehler auf.");
    if (wmilog) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + wmilog); 
  }else if(!CPSGENERAL){
   result = string("Fehler");
   desc = string("Beim Testen des Systems trat ein Fehler auf.\nEs konnte keine RSOP Abfrage durchgef�hrt werden.");
  }else if (PAGEFILE == "1"){
    result = string("erf�llt");
    desc = string('Das l�schen der Auslagerungsdatei des virtuellen\nArbeitspeichers ist aktiviert.');
  }else{
    result = string("nicht erf�llt");
    desc = string('Das l�schen der Auslagerungsdatei des virtuellen\nArbeitspeichers ist nicht aktiviert.');
  }

}else{
  if(cryptsetupinst == "windows") {
    result = string("Fehler");
    if (OSNAME >!< "none" && OSNAME >!< "error") desc = string('Folgendes System wurde erkannt:\n' + OSNAME + '\nAllerdings konnte auf das System nicht korrekt\nzugegriffen werden. Folgende Fehler sind aufgetreten:\n' + WMIOSLOG);
    else desc = string('Das System scheint ein Windows-System zu sein.\nAllerdings konnte auf das System nicht korrekt\nzugegriffen werden. Folgende Fehler sind aufgetreten:\n' + WMIOSLOG);
  }else if(cryptsetupinst == "error"){
    result = string("Fehler");
    if (!sshlog) desc = string("Beim Testen des Systems trat ein Fehler auf.");
    if (sshlog) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + sshlog); 
  }else if(cryptsetupinst == "no"){
    result = string("nicht erf�llt");
    desc = string('Das Paket cryptsetup ist nicht installiert.\nDavon ausgehend ist die SWAP Partition nicht\nverschl�sselt.');
  }else if(cryptsetupinst == "yes" && cryptsetupfstab == "no"){
    result = string("nicht erf�llt");
    desc = string('Das Paket cryptsetup ist installiert. Allerdings wurde\nkein Entsprechender Eintrag f�r eine verschl�sselte\nSWAP Partition in /etc/fstab gefunden.');
  }else if(cryptsetupinst == "yes" && cryptsetupfstab != "no"){
    result = string("erf�llt");
    desc = string('Das Paket cryptsetup ist installiert. Es wurde\nfolgender Eintrag f�r eine verschl�sselte SWAP\nPartition in /etc/fstab gefunden:\n' + cryptsetupfstab);
  }
}

if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler\nauf bzw. es konnte kein Ergebnis ermittelt werden.'); 
}

set_kb_item(name:"GSHB-12/M4_325/result", value:result);
set_kb_item(name:"GSHB-12/M4_325/desc", value:desc);
set_kb_item(name:"GSHB-12/M4_325/name", value:name);

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
