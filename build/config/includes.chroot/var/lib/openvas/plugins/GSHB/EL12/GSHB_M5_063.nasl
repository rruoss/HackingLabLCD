###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M5_063.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 12. EL, Maﬂnahme 5.063
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
tag_summary = "IT-Grundschutz M5.063: Einsatz von GnuPG oder PGP.

Diese Pr¸fung bezieht sich auf die 12. Erg‰nzungslieferung (12. EL) des IT-
Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

http://www.bsi.bund.de/grundschutz/kataloge/m/m05/m05063.html";


if(description)
{
  script_id(95012);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2011-11-07 13:38:53 +0100 (Mon, 07 Nov 2011)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M5.063: Einsatz von GnuPG oder PGP");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("IT-Grundschutz M5.063: Einsatz von GnuPG oder PGP.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-12");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-12");
  script_dependencies("gather-package-list.nasl", "GSHB/GSHB_WMI_GnuPGandPGP.nasl", "GSHB/GSHB_SSH_pubring.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  script_require_keys("WMI/GnuPGVersion");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M5.063: Einsatz von GnuPG oder PGP\n';

GnuPGVersion = get_kb_item("WMI/GnuPGVersion");
PGPVersion = get_kb_item("WMI/PGPVersion");
GnuPGpubringsUser = get_kb_item("WMI/GnuPGpubringsUser");
PGPpubringsUser = get_kb_item("WMI/PGPpubringsUser");
OSVER = get_kb_item("SMB/WindowsVersion");
OSNAME = get_kb_item("WMI/WMI_NAME");
wmilog = get_kb_item("WMI/PGP/log");
WMIOSLOG = get_kb_item("WMI/WMI_OS/log");
gshbm = "GSHB Maﬂnahme 5.063: ";

pubrings = get_kb_item("GSHB/pubrings");
log = get_kb_item("GSHB/pubrings/log");

SAMBA = get_kb_item("SMB/samba");
SSHUNAME = get_kb_item("ssh/login/uname");


if (SAMBA || (SSHUNAME && "command not found" >!< SSHUNAME && "CYGWIN" >!< SSHUNAME)){
  rpms = get_kb_item("ssh/login/packages");

  if (rpms){
    pkg1 = "gnupg";
    pkg2 = "gnupg2";

    pat1 = string("ii  (", pkg1, ") +([0-9]:)?([^ ]+)");
    pat2 = string("ii  (", pkg2, ") +([0-9]:)?([^ ]+)");
    desc1 = eregmatch(pattern:pat1, string:rpms);
    desc2 = eregmatch(pattern:pat2, string:rpms);

    name1 = desc1[1];
    version1 = desc1[3];
    name2 = desc2[1];
    version2 = desc2[3];
  }
  else{
    rpms = get_kb_item("ssh/login/rpms");
    tmp = split(rpms, keep:0);
    if (max_index(tmp) <= 1){
      tmp = split(rpms,sep:";", keep:0);
      rpms = "";
      for (i=0; i<max_index(tmp); i++){
      rpms += tmp[i] + '\n';
      }
    }
    pkg1 = "gnupg";
    pkg2 = "gnupg2";

    pat1 = string("(", pkg1, ")~([0-9/.]+)~([0-9a-zA-Z/.-_]+)");
    pat2 = string("(", pkg2, ")~([0-9/.]+)~([0-9a-zA-Z/.-_]+)");
    desc1 = eregmatch(pattern:pat1, string:rpms);
    desc2 = eregmatch(pattern:pat2, string:rpms);
    if (desc1){
      name1 = desc1[1];
      version1 = desc1[2];
    }
    if (desc2){
      name2 = desc2[1];
      version2 = desc2[2];
    }
  }
  if(pubrings == "windows") {
    result = string("Fehler");
    if (OSNAME >!< "none" && OSNAME >!< "error") desc = string('Folgendes System wurde erkannt:\n' + OSNAME + '\nAllerdings konnte auf das System nicht korrekt zugegriffen\nwerden. Folgende Fehler sind aufgetreten:\n' + wmilog);
    else desc = string('Das System scheint ein Windows-System zu sein. Allerdings\nkonnte auf das System nicht korrekt zugegriffen werden.\nFolgende Fehler sind aufgetreten:\n' + wmilog);
  }else if(pubrings >< "error"){
    result = string("Fehler");
    if (!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
    if (log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
  }else if(!SSHUNAME){
    result = string("Fehler");
    desc = string("Ein Login ¸ber SSH war nicht erfolgreich.");
  }else if(!rpms){
    result = string("Fehler");
    desc = string("Vom System konnte keine Paketliste mit installierter\nSoftware geladen werden.");
  }else if(!desc1 && !desc2){
    result = string("nicht zutreffend");
    desc = string("Auf dem System wurde keine GnuPG-Standardinstallation gefunden.");
  }else if(desc1 || desc2){
    result = string("erf¸llt");
    if (desc1 && !desc2)desc = string('Folgende GnuPG-Version ist installiert:\n' + name1 + "  " + version1 + '\nPr¸fen Sie, ob dies die aktuellste Version ist!\n');
    else if(desc2 && !desc1)desc = string('Folgende GnuPG-Version ist installiert:\n' + name2 + "  " + version2 + '\nPr¸fen Sie, ob dies die aktuellste Version ist!\n');
    else if(desc1 && desc2)desc = string('Folgende GnuPG-Version ist installiert:\n' + name1 + "  " + version1 + '\n' + name2 + "  " + version2 + '\nPr¸fen Sie, ob dies die aktuellste Version ist!\n');
    if(pubrings != "none") desc = desc + string('Folgende Benutzer setzen GnuPG ein:\n' + pubrings + '\n');
  }else{
      result = string("Fehler");
      desc = string("Beim Testen des Systems trat ein unbekannter Fehler auf.");
  }
}else{
  if(GnuPGVersion >< "error"){
    result = string("Fehler");
    if (!wmilog) desc = string("Beim Testen des Systems trat ein Fehler auf.");
    if (wmilog) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + wmilog);
  } else if(GnuPGVersion >< "none" && PGPVersion >< "none"){
    result = string("nicht zutreffend");
    desc = string("Auf dem System wurde keine GnuPG- bzw. PGP-Standardinstallation\ngefunden.");
  } else {
    result = string("erf¸llt");
    if(GnuPGVersion != "none") desc = string('Folgende GnuPG-Version ist installiert: ' + GnuPGVersion + '\nPr¸fen Sie, ob dies die aktuellste Version ist!\n') ;
    if(GnuPGpubringsUser != "none") desc = desc + string('Folgende Benutzer setzen GnuPG ein:\n' + GnuPGpubringsUser + '\n');
    if(PGPVersion != "none") desc = desc + string('Folgende PGP-Version ist installiert: ' + PGPVersion + '\nPr¸fen Sie, ob dies die aktuellste Version ist!\n') ;
    if(PGPpubringsUser != "none"){
      PGPpubringsUser = ereg_replace(string:PGPpubringsUser, pattern: ' ;', replace:';\\n');
      desc = desc + string('Folgende Benutzer setzen PGP ein:\n' + PGPpubringsUser + '\n');
    }
  }
}

set_kb_item(name:"GSHB-12/M5_063/result", value:result);
set_kb_item(name:"GSHB-12/M5_063/desc", value:desc);
set_kb_item(name:"GSHB-12/M5_063/name", value:name);

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
