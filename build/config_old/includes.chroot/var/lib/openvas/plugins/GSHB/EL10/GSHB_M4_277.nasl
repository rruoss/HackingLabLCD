###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_277.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 10. EL, Maﬂnahme 4.277
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
tag_summary = "IT-Grundschutz M4.277: Absicherung der SMB-, LDAP- und RPC-Kommunikation unter Windows Server 2003(Win).

  Diese Pr¸fung bezieht sich auf die 10. Erg‰nzungslieferung (10. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
  Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

  http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04277.html";


if(description)
{
  script_id(94277);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Thu Jan 14 14:29:35 2010 +0100");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.277: Absicherung der SMB-, LDAP- und RPC-Kommunikation unter Windows Server 2003(Win)");
  if (! OPENVAS_VERSION)
  {
    desc = "
    Leider setzen Sie einen zu alten OpenVAS Scan-Server ein.
    Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!";
    script_description(desc);
    script_summary("IT-Grundschutz M4.277: Absicherung der SMB-, LDAP- und RPC-Kommunikation unter Windows Server 2003(Win).");
    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
    script_family("IT-Grundschutz-10");
    exit(0);
  }
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("IT-Grundschutz M4.277: Absicherung der SMB-, LDAP- und RPC-Kommunikation unter Windows Server 2003(Win).");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-10");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-10");
  script_dependencies("GSHB/GSHB_WMI_PolSecSet.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  script_require_keys("WMI/WMI_OSVER");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.277: Absicherung der SMB-, LDAP- und RPC-Kommunikation unter Windows Server 2003(Win)\n';

if (! OPENVAS_VERSION)
{
        set_kb_item(name:"GSHB-10/M4_277/result", value:"nicht zutreffend");
        set_kb_item(name:"GSHB-10/M4_277/desc", value:"Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!");
        set_kb_item(name:"GSHB-10/M4_277/name", value:name);
    log_message(port:0, proto: "IT-Grundschutz", data:string("Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!"));  
    exit(0);
}


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
  desc = string("Auf dem System l‰uft Samba, es ist kein Microsoft System.");
}else if("error" >< CPSGENERAL){
  result = string("Fehler");
  if (!log) desc = string("Beim Testen des Systems trat ein Fehler auf, siehe Log Message!");
  if (log) desc = string("Beim Testen des Systems trat ein Fehler auf: " + log);
}else if(OSVER != '5.2' || OSNAME >< 'Microsoft(R) Windows(R) XP Professional x64 Edition'){
  result = string("nicht zutreffend");
  desc = string("Das System ist kein Windows 2003 Server.");
}else if (NTLMMinServerSec == "537395248" && requiresignorseal == "1" && requirestrongkey == "1" && RequireSecuritySignatureWs == "1" && EnablePlainTextPassword == "0" && RequireSecuritySignatureSvr == "1" && EnableSecuritySignatureSvr == "1" && NoLMHash == "1" && lmcomplevel >= "5" && LDAPClientIntegrity == "1" && NTLMMinClientSec == "537395248")
{
  result = string("erf¸llt");
  desc = string("Die Sicherheitseinstellung stimmen mit der Maﬂnahme M4.277 ¸berein.");
}else{
  result = string("nicht erf¸llt");
  if (NTLMMinServerSec != "537395248") val = val + '\n' + "Netzwerksicherheit: Minimale Sitzungssicherheit f¸r NTLM-SSP-basierte Server (einschlieﬂlich sicherer RPC-Server)";
  if (requiresignorseal != "1") val = val + '\n' + "Dom‰nenmitglied: Daten des sicheren Kanals digital verschl¸sseln oder signieren (immer)";
  if (requirestrongkey != "1") val = val + '\n' + "Dom‰nenmitglied: Starker Sitzungsschl¸ssel erforderlich (Windows 2000 oder hˆher)";
  if (RequireSecuritySignatureWs != "1") val = val + '\n' + "Microsoft-Netzwerk (Server): Kommunikation digital signieren (immer)";
  if (EnablePlainTextPassword != "0") val = val + '\n' + "Microsoft-Netzwerk (Client): Unverschl¸sseltes Kennwort an SMB-Server von Drittanbietern senden";
  if (RequireSecuritySignatureSvr != "1") val = val + '\n' + "Microsoft-Netzwerk (Client): Kommunikation digital signieren (immer)";
  if (EnableSecuritySignatureSvr != "1") val = val + '\n' + "Microsoft-Netzwerk (Server): Kommunikation digital signieren (wenn Client zustimmt)";
  if (NoLMHash != "1") val = val + '\n' + "Netzwerksicherheit: Keine LAN Manager-Hashwerte f¸r n‰chste Kennwort‰nderung speichern";
  if (lmcomplevel != "5") val = val + '\n' + "Netzwerksicherheit: LAN Manager-Authentifizierungsebene";
  if (LDAPClientIntegrity != "1") val = val + '\n' + "Netzwerksicherheit: Signaturanforderungen f¸r LDAP-Clients";
  if (NTLMMinClientSec != "537395248") val = val + '\n' + "Netzwerksicherheit: Minimale Sitzungssicherheit f¸r NTLM-SSP-basierte Clients (einschlieﬂlich sicherer RPC-Clients)";

  desc = string("Die Sicherheitseinstellung stimmen nicht mit der Maﬂnahme M4.277 ‹berein. Folgende Einstellungen sind nicht, wie im Dokument 'Windows Server 2003 Security Baseline Settings' gefordert, umgesetzt: " + val);
}


set_kb_item(name:"GSHB-10/M4_277/result", value:result);
set_kb_item(name:"GSHB-10/M4_277/desc", value:desc);
set_kb_item(name:"GSHB-10/M4_277/name", value:name);


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
