###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_277.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 12. EL, Ma�nahme 4.277
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
tag_summary = "IT-Grundschutz M4.277: Absicherung der SMB-, LDAP- und RPC-Kommunikation unter Windows Server 2003(Win).

Diese Pr�fung bezieht sich auf die 12. Erg�nzungslieferung (12. EL) des IT-
Grundschutz. Die detaillierte Beschreibung zu dieser Ma�nahme findet sich unter
nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
die aktuellste Erg�nzungslieferung bezieht. Titel und Inhalt k�nnen sich bei einer
Aktualisierung �ndern, allerdings nicht die Kernthematik.

http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04277.html";


if(description)
{
  script_id(94070);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2011-11-07 13:38:53 +0100 (Mon, 07 Nov 2011)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.277: Absicherung der SMB-, LDAP- und RPC-Kommunikation unter Windows Server 2003(Win)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("IT-Grundschutz M4.277: Absicherung der SMB-, LDAP- und RPC-Kommunikation unter Windows Server 2003(Win).");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-12");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-12");
  script_dependencies("GSHB/GSHB_WMI_PolSecSet.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  script_require_keys("WMI/WMI_OSVER");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.277: Absicherung der SMB-, LDAP- und RPC-Kommunikation unter Windows Server 2003(Win)\n';

gshbm =  "IT-Grundschutz M4.277: ";
CPSGENERAL = get_kb_item("WMI/cps/GENERAL");
log = get_kb_item("WMI/cps/GENERAL/log");
OSVER = get_kb_item("WMI/WMI_OSVER");
OSNAME = get_kb_item("WMI/WMI_OSNAME");
WMIOSLOG = get_kb_item("WMI/WMI_OS/log");
NTLMMinServerSec = get_kb_item("WMI/cps/NTLMMinServerSec");
requiresignorseal = get_kb_item("WMI/cps/requiresignorseal");
requirestrongkey = get_kb_item("WMI/cps/requirestrongkey");
RequireSecuritySignatureWs = get_kb_item("WMI/cps/RequireSecuritySignatureWs");
EnablePlainTextPassword = get_kb_item("WMI/cps/EnablePlainTextPassword");
RequireSecuritySignatureSvr = get_kb_item("WMI/cps/RequireSecuritySignatureSvr");
EnableSecuritySignatureSvr = get_kb_item("WMI/cps/EnableSecuritySignatureSvr");
NoLMHash = get_kb_item("WMI/cps/NoLMHash");
lmcomplevel = get_kb_item("WMI/scp/LMCompatibilityLevel");
LDAPClientIntegrity = get_kb_item("WMI/cps/LDAPClientIntegrity");
NTLMMinClientSec = get_kb_item("WMI/cps/NTLMMinClientSec");


if (WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System."){
  result = string("nicht zutreffend");
  desc = string("Auf dem System l�uft Samba,\nes ist kein Microsoft Windows System.");
}else if("error" >< CPSGENERAL){
  result = string("Fehler");
  if(!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
  if(log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
}else if(!CPSGENERAL){
  result = string("Fehler");
  desc = string("Beim Testen des Systems trat ein Fehler auf.\nEs konnte keine RSOP Abfrage durchgef�hrt werden.");
}else if(OSVER != '5.2' || OSNAME >< 'Microsoft(R) Windows(R) XP Professional x64 Edition'){
  result = string("nicht zutreffend");
  desc = string("Das System ist kein Windows 2003 Server.");
}else if (NTLMMinServerSec == "537395248" && requiresignorseal == "1" && requirestrongkey == "1" && RequireSecuritySignatureWs == "1" && EnablePlainTextPassword == "0" && RequireSecuritySignatureSvr == "1" && EnableSecuritySignatureSvr == "1" && NoLMHash == "1" && lmcomplevel >= "5" && LDAPClientIntegrity == "1" && NTLMMinClientSec == "537395248")
{
  result = string("erf�llt");
  desc = string("Die Sicherheitseinstellung stimmen mit der Ma�nahme\nM4.277 �berein.");
}else{
  result = string("nicht erf�llt");
  if (NTLMMinServerSec != "537395248") val = val + '\n\n' + "Netzwerksicherheit: Minimale Sitzungssicherheit f�r\nNTLM-SSP-basierte Server (einschlie�lich sicherer\nRPC-Server)";
  if (requiresignorseal != "1") val = val + '\n\n' + "Dom�nenmitglied: Daten des sicheren Kanals digital\nverschl�sseln oder signieren (immer)";
  if (requirestrongkey != "1") val = val + '\n\n' + "Dom�nenmitglied: Starker Sitzungsschl�ssel erforder-\nlich (Windows 2000 oder h�her)";
  if (RequireSecuritySignatureWs != "1") val = val + '\n\n' + "Microsoft-Netzwerk (Server): Kommunikation digital\nsignieren (immer)";
  if (EnablePlainTextPassword != "0") val = val + '\n\n' + "Microsoft-Netzwerk (Client): Unverschl�sseltes\nKennwort an SMB-Server von Drittanbietern senden";
  if (RequireSecuritySignatureSvr != "1") val = val + '\n\n' + "Microsoft-Netzwerk (Client): Kommunikation digital\nsignieren (immer)";
  if (EnableSecuritySignatureSvr != "1") val = val + '\n\n' + "Microsoft-Netzwerk (Server): Kommunikation digital\nsignieren (wenn Client zustimmt)";
  if (NoLMHash != "1") val = val + '\n\n' + "Netzwerksicherheit: Keine LAN Manager-Hashwerte f�r\nn�chste Kennwort�nderung speichern";
  if (lmcomplevel != "5") val = val + '\n\n' + "Netzwerksicherheit: LAN Manager-Authentifizierungs-\nebene";
  if (LDAPClientIntegrity != "1") val = val + '\n\n' + "Netzwerksicherheit: Signaturanforderungen f�r LDAP-\nClients";
  if (NTLMMinClientSec != "537395248") val = val + '\n\n' + "Netzwerksicherheit: Minimale Sitzungssicherheit f�r\nNTLM-SSP-basierte Clients (einschlie�lich sicherer\nRPC-Clients)";

  desc = string("Die Sicherheitseinstellung stimmen nicht mit der\nMa�nahme M4.277 �berein. Folgende Einstellungen sind\nnicht wie im Dokument 'Windows Server 2003 Security\nBaseline Settings' gefordert umgesetzt: " + val);
}

set_kb_item(name:"GSHB-12/M4_277/result", value:result);
set_kb_item(name:"GSHB-12/M4_277/desc", value:desc);
set_kb_item(name:"GSHB-12/M4_277/name", value:name);


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
