###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M5_131.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 10. EL, Maﬂnahme 5.131
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
tag_summary = "IT-Grundschutz M5.131: Absicherung von IP-Protokollen unter Windows Server 2003(Win).

  Diese Pr¸fung bezieht sich auf die 10. Erg‰nzungslieferung (10. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
  Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

  http://www.bsi.bund.de/grundschutz/kataloge/m/m05/m05131.html";


if(description)
{
  script_id(95131);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Thu Jan 14 14:29:35 2010 +0100");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M5.131: Absicherung von IP-Protokollen unter Windows Server 2003(Win)");
  if (! OPENVAS_VERSION)
  {
    desc = "
    Leider setzen Sie einen zu alten OpenVAS Scan-Server ein.
    Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!";
    script_description(desc);
    script_summary("IT-Grundschutz M5.131: Absicherung von IP-Protokollen unter Windows Server 2003(Win).");
    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
    script_family("IT-Grundschutz-10");
    exit(0);
  }
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("IT-Grundschutz M5.131: Absicherung von IP-Protokollen unter Windows Server 2003(Win).");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-10");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-10");
  script_dependencies("GSHB/GSHB_WMI_PolSecSet.nasl", "GSHB/GSHB_WMI_OSInfo.nasl", "GSHB/GSHB_WMI_IIS_Protect_SynAttack.nasl", "GSHB/GSHB_WMI_NtpServer.nasl", "GSHB/GSHB_WMI_SNMP_Communities.nasl");
  script_require_keys("WMI/WMI_OSVER");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M5.131: Absicherung von IP-Protokollen unter Windows Server 2003(Win)\n';

if (! OPENVAS_VERSION)
{
        set_kb_item(name:"GSHB-10/M5_131/result", value:"nicht zutreffend");
        set_kb_item(name:"GSHB-10/M5_131/desc", value:"Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!");
        set_kb_item(name:"GSHB-10/M5_131/name", value:name);
    log_message(port:0, proto: "IT-Grundschutz", data:string("Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!"));  
    exit(0);
}


gshbm =  "IT-Grundschutz M5.131: ";
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

DisableIPSourceRouting = get_kb_item("WMI/cps/DisableIPSourceRouting");
EnableDeadGWDetect = get_kb_item("WMI/cps/EnableDeadGWDetect");
EnableICMPRedirect = get_kb_item("WMI/cps/EnableICMPRedirect");
NoNameReleaseOnDemand = get_kb_item("WMI/cps/NoNameReleaseOnDemand");
PerformRouterDiscovery = get_kb_item("WMI/cps/PerformRouterDiscovery");
SynAttackProtect = get_kb_item("WMI/cps/SynAttackProtect");
TcpMaxConnectResponseRetransmissions = get_kb_item("WMI/cps/TcpMaxConnectResponseRetransmissions");
TcpMaxDataRetransmissions = get_kb_item("WMI/cps/TcpMaxDataRetransmissions");
KeepAliveTime = get_kb_item("WMI/cps/KeepAliveTime");

TcpMaxPortsExhausted = get_kb_item("WMI/TcpMaxPortsExhausted");
MinimumDynamicBacklog = get_kb_item("WMI/MinimumDynamicBacklog");
MaximumDynamicBacklog = get_kb_item("WMI/MaximumDynamicBacklog");
EnableDynamicBacklog = get_kb_item("WMI/EnableDynamicBacklog");
DynamicBacklogGrowthDelta = get_kb_item("WMI/DynamicBacklogGrowthDelta");

ntpserver = get_kb_item("WMI/NtpServer");
ntpserver = tolower(ntpserver);
domain = get_kb_item("WMI/WMI_WindowsDomain");
domain = tolower(domain);

if (ntpserver >!< "none" && ntpserver >!< "error") ntpserver = split(ntpserver, sep:",", keep:0);


SNMPCommunities = get_kb_item("WMI/SNMPCommunities");
SNMPCommunities = tolower(SNMPCommunities);

DefaultCommunity = "false";
SNMPCommunitiesSP = split(SNMPCommunities, sep:'|', keep:0);

for(i=0; i<max_index(SNMPCommunitiesSP); i++)
{
  if (SNMPCommunitiesSP[i] == "public" || SNMPCommunitiesSP[i] == "private")
  {
    DefCom = "true";
    set_kb_item(name:"GSHB-10/M5_131/DefCom" + i, value:DefCom);

    set_kb_item(name:"GSHB-10/M5_131/ExistComm" + i, value:ExistComm);
  }
  else DefCom = "false";
  if (DefCom == "true" && DefaultCommunity == "true")
  {
    DefaultCommunity = "true";
  }
  else if (DefCom == "false" && DefaultCommunity == "true")
  {
    DefaultCommunity = "true";
  }
  else if (DefCom == "true" && DefaultCommunity == "false")
  {
    DefaultCommunity = "true";
  }
  else DefaultCommunity = "false";
}

if (WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System."){
  result = string("nicht zutreffend");
  desc = string("Auf dem System l‰uft Samba, es ist kein Microsoft System.");
}else if("error" >< CPSGENERAL){
  result = string("Fehler");
  if(!log) desc = string("Beim Testen des Systems trat ein Fehler auf, siehe Log Message!");
  if(log) desc = string("Beim Testen des Systems trat ein Fehler auf: " + log);
}else if(OSVER != '5.2' || OSNAME >< 'Microsoft(R) Windows(R) XP Professional x64 Edition'){
  result = string("nicht zutreffend");
  desc = string("Das System ist kein Windows 2003 Server.");
}else if(NTLMMinServerSec == "537395248" && requiresignorseal == "1" && requirestrongkey == "1" && RequireSecuritySignatureWs == "1" && EnablePlainTextPassword == "0" && RequireSecuritySignatureSvr == "1" && EnableSecuritySignatureSvr == "1" && NoLMHash == "1" && lmcomplevel >= "5" && LDAPClientIntegrity == "1" && NTLMMinClientSec == "537395248" && domain >< ntpserver[0] && DisableIPSourceRouting == "2" && EnableDeadGWDetect =="0" && EnableICMPRedirect == "0" && NoNameReleaseOnDemand == "1" && PerformRouterDiscovery == "0" && SynAttackProtect =="1" && TcpMaxConnectResponseRetransmissions == "3" && TcpMaxDataRetransmissions == "3" && KeepAliveTime == "300000" && TcpMaxPortsExhausted == "5" && MinimumDynamicBacklog == "20" && MaximumDynamicBacklog == "20000" && EnableDynamicBacklog == "1" && DynamicBacklogGrowthDelta == "10" && DefaultCommunity == "false")
{
  result = string("erf¸llt");
  desc = string("Die Sicherheitseinstellung stimmen mit der Maﬂnahme M5.131 ¸berein.");
}else{
  result = string("nicht erf¸llt");
    if (DisableIPSourceRouting != "2") val = val + '\n' + "MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)";
  if (EnableDeadGWDetect != "0") val = val + '\n' + "MSS: (EnableDeadGWDetect) Allow automatic detection of dead network gateways (could lead to DoS)";
  if (EnableICMPRedirect != "0") val = val + '\n' + "MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes";
  if (EnablePlainTextPassword != "0") val = val + '\n' + "Microsoft-Netzwerk (Client): Unverschl¸sseltes Kennwort an SMB-Server von Drittanbietern senden";
  if (EnableSecuritySignatureSvr != "1") val = val + '\n' + "Microsoft-Netzwerk (Server): Kommunikation digital signieren (wenn Client zustimmt)";
  if (KeepAliveTime != "300000") val = val + '\n' + "MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds";
  if (LDAPClientIntegrity != "1") val = val + '\n' + "Netzwerksicherheit: Signaturanforderungen f¸r LDAP-Clients";
  if (lmcomplevel != "5") val = val + '\n' + "Netzwerksicherheit: LAN Manager-Authentifizierungsebene";
  if (NoLMHash != "1") val = val + '\n' + "Netzwerksicherheit: Keine LAN Manager-Hashwerte f¸r n‰chste Kennwort‰nderung speichern";
  if (NoNameReleaseOnDemand != "1") val = val + '\n' + "MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers";
  if (NTLMMinClientSec != "537395248") val = val + '\n' + "Netzwerksicherheit: Minimale Sitzungssicherheit f¸r NTLM-SSP-basierte Clients (einschlieﬂlich sicherer RPC-Clients)";
  if (NTLMMinServerSec != "537395248") val = val + '\n' + "Netzwerksicherheit: Minimale Sitzungssicherheit f¸r NTLM-SSP-basierte Server (einschlieﬂlich sicherer RPC-Server)";
  if (PerformRouterDiscovery != "0") val = val + '\n' + "MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)";
  if (RequireSecuritySignatureSvr != "1") val = val + '\n' + "Microsoft-Netzwerk (Client): Kommunikation digital signieren (immer)";
  if (RequireSecuritySignatureWs != "1") val = val + '\n' + "Microsoft-Netzwerk (Server): Kommunikation digital signieren (immer)";
  if (requiresignorseal != "1") val = val + '\n' + "Dom‰nenmitglied: Daten des sicheren Kanals digital verschl¸sseln oder signieren (immer)";
  if (requirestrongkey != "1") val = val + '\n' + "Dom‰nenmitglied: Starker Sitzungsschl¸ssel erforderlich (Windows 2000 oder hˆher)";
  if (SynAttackProtect != "1") val = val + '\n' + "MSS: (SynAttackProtect) Syn attack protection level (protects against DoS)";
  if (TcpMaxConnectResponseRetransmissions != "3") val = val + '\n' + "MSS: (TCPMaxConnectResponseRetransmissions) SYN-ACK retransmissions when a connection request is not acknowledged";
  if (TcpMaxDataRetransmissions != "3") val = val + '\n' + "MSS: (TCPMaxDataRetransmissions) How many times unacknowledged data is retransmitted (3 recommended, 5 is default)";
  if (TcpMaxPortsExhausted != "5") val = val + '\n' + "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tcpip\Parameters\TcpMaxPortsExhausted";
  if (DynamicBacklogGrowthDelta != "10") val = val + '\n' + "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD\Parameters\DynamicBacklogGrowthDelta";
  if (EnableDynamicBacklog != "1") val = val + '\n' + "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD\Parameters\EnableDynamicBacklog";
  if (MaximumDynamicBacklog != "20000") val = val + '\n' + "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD\Parameters\MaximumDynamicBacklog";
  if (MinimumDynamicBacklog != "20") val = val + '\n' + "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD\Parameters\MinimumDynamicBacklog";  if (domain >!< ntpserver[0]) val = val + '\n' + "Auf dem System wurde ein EXTERNER NTP Server hinterlegt: " + ntpserver[0];
  if (DefaultCommunity != "false") val = val + '\n' + "Folgende Default Communities existieren: " + ExistComm;

  desc = string("Die Sicherheitseinstellung stimmen nicht mit der Maﬂnahme M5.123 ‹berein. Folgende Einstellungen sind nicht wie  gefordert umgesetzt: " + val);
}



set_kb_item(name:"GSHB-10/M5_131/result", value:result);
set_kb_item(name:"GSHB-10/M5_131/desc", value:desc);
set_kb_item(name:"GSHB-10/M5_131/name", value:name);


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
