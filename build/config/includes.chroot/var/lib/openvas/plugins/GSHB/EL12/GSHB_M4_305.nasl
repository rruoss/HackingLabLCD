###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_305.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 12. EL, Maﬂnahme 4.305
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
tag_summary = "IT-Grundschutz M4.305: Einsatz von Speicherbeschr‰nkungen (Quotas).

Diese Pr¸fung bezieht sich auf die 12. Erg‰nzungslieferung (12. EL) des IT-
Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04305.html";

if(description)
{
  script_id(94076);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2011-11-07 13:38:53 +0100 (Mon, 07 Nov 2011)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.305: Einsatz von Speicherbeschr‰nkungen (Quotas)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("IT-Grundschutz M4.305: Einsatz von Speicherbeschr‰nkungen (Quotas).");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-12");
  script_mandatory_keys("Compliance/Launch/GSHB-12");
  script_dependencies("GSHB/GSHB_SSH_quota.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.305: Einsatz von Speicherbeschr‰nkungen (Quotas)\n';

gshbm =  "IT-Grundschutz M4.305: ";

uname = get_kb_item("GSHB/quota/uname");
fstab = get_kb_item("GSHB/quota/fstab");
user = get_kb_item("GSHB/quota/user");
group = get_kb_item("GSHB/quota/group");
log = get_kb_item("GSHB/quota/log");
zfsquota = get_kb_item("GSHB/quota/zfsquota");
ufsquota = get_kb_item("GSHB/quota/ufsquota");
   
OSNAME = get_kb_item("WMI/WMI_OSNAME");

if(OSNAME >!< "none"){
  result = string("nicht zutreffend");
  desc = string('Folgendes System wurde erkannt:\n' + OSNAME);
}else if(fstab == "windows") {
    result = string("nicht zutreffend");
    desc = string('Das System scheint ein Windows-System zu sein.');
}else if(uname =~ "SunOS.*"){
    if(ufsquota >< "norepquota" && zfsquota >< "nozfs"){
    result = string("Fehler");
    desc = string('Auf dem System konnte weder der Befehl "repquota -va" noch der\nBefehl "zfs get quota", zum ermitteln der Quotaeinstellungen,\nausgef¸hrt werden.'); 
  }else if(ufsquota >< "noquota" && zfsquota >< "noquota"){
    result = string("nicht erf¸llt");
    desc = string('Auf dem System konnten keine Quotaeinstellungen\ngefunden werden.'); 
  }else if ((ufsquota >!< "noquota" && ufsquota >!< "norepquota") || (zfsquota >!< "noquota" && zfsquota >!< "nozfs")){
    result = string("erf¸llt");
    desc = string('Auf dem System konnten folgende Volumes mit\nQuotaeinstellungen gefunden werden:'); 
    if (ufsquota >!< "noquota" && ufsquota >!< "norepquota")desc += string('\n' + ufsquota);
    if (zfsquota >!< "noquota" && zfsquota >!< "nozfs")desc += string('\n' + zfsquota); 
  }else{
  result = string("Fehler");
  if (!log)desc = string('Beim Testen des Systems trat ein unbekannter\nFehler auf.');
  if (log)desc = string('Beim Testen des Systems trat ein Fehler auf:\n' + log);
  }
}else if(fstab >< "error"){
  result = string("Fehler");
  if (!log)desc = string('Beim Testen des Systems trat ein unbekannter\nFehler auf.');
  if (log)desc = string('Beim Testen des Systems trat ein Fehler auf:\n' + log);
}else if(fstab >< "none"){
  result = string("nicht erf¸llt");
  desc = string('Auf dem System konnten keine Quotaeinstellungen\ngefunden werden.'); 
}else if(((user >!< "none" && user >!< "nols") || (group >!< "none" && group >!< "nols")) && (fstab >!< "none" && fstab != "nogrep")){
  result = string("erf¸llt");
  desc = string('Auf dem System konnten folgende Volumes mit Quota-\neinstellungen gefunden werden:\n' + fstab); 
}else if (user >< "nols" || group >< "nols" || fstab >< "nogrep"){
  result = string("Fehler");
  if (user >< "nols" || group >< "nols")  desc = string('Beim Testen des Systems wurde der Befehl ls\nnicht gefunden.\n'); 
  if (fstab >< "nogrep")  desc += string('Beim Testen des Systems wurde der Befehl grep\nnicht gefunden.'); 
}

set_kb_item(name:"GSHB-12/M4_305/result", value:result);
set_kb_item(name:"GSHB-12/M4_305/desc", value:desc);
set_kb_item(name:"GSHB-12/M4_305/name", value:name);

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
