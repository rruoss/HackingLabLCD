###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_313.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 10. EL, Maﬂnahme 4.313
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
tag_summary = "IT-Grundschutz M4.313: Bereitstellung von sicheren Dom‰nen-Controllern (Win).

  Diese Pr¸fung bezieht sich auf die 10. Erg‰nzungslieferung (10. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
  Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

  http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04313.html";


if(description)
{
  script_id(94313);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Thu Jan 14 14:29:35 2010 +0100");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.313: Bereitstellung von sicheren Dom‰nen-Controllern (Win)");
  if (! OPENVAS_VERSION)
  {
    desc = "
    Leider setzen Sie einen zu alten OpenVAS Scan-Server ein.
    Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!";
    script_description(desc);
    script_summary("IT-Grundschutz M4.313: Bereitstellung von sicheren Dom‰nen-Controllern (Win).");
    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
    script_family("IT-Grundschutz-10");
    exit(0);
  }
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("IT-Grundschutz M4.313: Bereitstellung von sicheren Dom‰nen-Controllern (Win).");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-10");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-10");
  script_dependencies("GSHB/GSHB_WMI_PolSecSet.nasl", "GSHB/GSHB_WMI_OSInfo.nasl", "GSHB/GSHB_WMI_DomContrTest.nasl", "GSHB/GSHB_WMI_pre2000comp.nasl", "GSHB/GSHB_SMB_SDDL.nasl");

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.313: Bereitstellung von sicheren Dom‰nen-Controllern (Win)\n';
gshbm =  "IT-Grundschutz M4.313: ";
CPSGENERAL = get_kb_item("WMI/cps/GENERAL");
OSVER = get_kb_item("WMI/WMI_OSVER");
OSTYPE = get_kb_item("WMI/WMI_OSTYPE");
WMIOSLOG = get_kb_item("WMI/WMI_OS/log");
ClientSiteName = get_kb_item("WMI/ClientSiteName");
PreWin2000Usr = get_kb_item("WMI/PreWin2000Usr");
NtfsDisable8dot3NameCreation = get_kb_item("WMI/cps/NtfsDisable8dot3NameCreation");
rootsddl = get_kb_item("WMI/ROOTSDDL");
log = get_kb_item("WMI/cps/GENERAL/log");

if (rootsddl != "None")
{
  rootsddlres =  eregmatch(pattern:'(\\(.*\\))?(\\(.*WD\\))', string:rootsddl);
}
else rootsddlres[2] = rootsddl;


if (WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System."){
  result = string("nicht zutreffend");
  desc = string("Auf dem System l‰uft Samba, es ist kein Microsoft System.");
}else if("error" >< CPSGENERAL)
{
  result = string("Fehler");
  if(!log) desc = string("Beim Testen des Systems trat ein Fehler auf, siehe Log Message!");
  if(log) desc = string("Beim Testen des Systems trat ein Fehler auf: " +log );  
}
else if((OSVER == '6.1' && OSTYPE == '2') || (OSVER == '6.0' && OSTYPE == '2') || (OSVER == '5.0' && ClientSiteName != "nodc") || (OSVER == '5.2' && ClientSiteName != "nodc"))
{
  if (NtfsDisable8dot3NameCreation == "1" && PreWin2000Usr == "None" && (rootsddlres[2] =~ "\(A;[OICNP]*;(0x00120089)?(0x001200a9)?(FR)?;;;WD\)" || !rootsddlres[2]))
  {
    result = string("erf¸llt");
    desc = string('Die Sicherheitseinstellung stimmen mit der Maﬂnahme M4.313 ¸berein.\nBitte beachten Sie auch den Punkt "Neustart-Schutz mit SYSKEY" in dieser Massnahme');
  }
  else
  {
    result = string("nicht erf¸llt");
    if (NtfsDisable8dot3NameCreation != "1") val = 'NtfsDisable8dot3NameCreation ist nicht auf den Wert -1- gesetzt.\n';
    if (PreWin2000Usr != "None") val = val + 'Der User -Jeder- befindet sich in der Gruppe Pr‰-Windows 2000 kompatibler Zugriff.\nBitte entfernen Sie ihn daraus.\n';
    if (rootsddlres[2] == "None") val = val + 'Die Berechtigung f¸r das Root Laufwerk konnte nicht gelesen werden';
    else if (rootsddlres[2] !~ "\(A;[OICNP]*;(0x00120089)?(0x001200a9)?(FR)?;;;WD\)") val = val + 'Die Berechtigung f¸r das Root Laufwerk sind falsch gesetzt.\nDie Berechtigungen f¸r die Gruppe -Jeder- sollte auf -Lesen und Ausf¸hren- eingegrenzt werden.';

    desc = string('Die Sicherheitseinstellung stimmen nicht mit der Maﬂnahme M4.313 ¸berein.\n' + val + '\nBitte beachten Sie auch den Punkt -Neustart-Schutz mit SYSKEY- in dieser Massnahme');
  }
}
else
{
  result = string("nicht zutreffend");
  desc = string("Das System ist kein Domaincontroller.");
}


set_kb_item(name:"GSHB-10/M4_313/result", value:result);
set_kb_item(name:"GSHB-10/M4_313/desc", value:desc);
set_kb_item(name:"GSHB-10/M4_313/name", value:name);

silence = get_kb_item("GSHB-10/silence");

if (silence){
exit(0);
} else {
  report = 'Ergebnisse zum IT-Grundschutz, 10. Erg‰nzungslieferung:\n\n';
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
