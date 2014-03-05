###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M5_123.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 11. EL, Maßnahme 5.123
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
tag_summary = "IT-Grundschutz M5.123: Absicherung der Netzkommunikation unter Windows (Win).

  Diese Prüfung bezieht sich auf die 11. Ergänzungslieferung (11. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Maßnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Ergänzungslieferung bezieht. Titel und Inhalt können sich bei einer
  Aktualisierung ändern, allerdings nicht die Kernthematik.

  http://www.bsi.bund.de/grundschutz/kataloge/m/m05/m05123.html";


if(description)
{
  script_id(895123);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Thu Jan 14 14:29:35 2010 +0100");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M5.123: Absicherung der Netzkommunikation unter Windows (Win)");
  if (! OPENVAS_VERSION)
  {
    desc = "
    Leider setzen Sie einen zu alten OpenVAS Scan-Server ein.
    Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!";
    script_description(desc);
    script_summary("IT-Grundschutz M5.123: Absicherung der Netzkommunikation unter Windows (Win).");
    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
    script_family("IT-Grundschutz-11");
    exit(0);
  }
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("IT-Grundschutz M5.123: Absicherung der Netzkommunikation unter Windows (Win).");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-11");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-11");
  script_dependencies("GSHB/GSHB_WMI_PolSecSet.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  script_require_keys("WMI/WMI_OSVER");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M5.123 Absicherung der Netzkommunikation unter Windows (Win)\n';

if (! OPENVAS_VERSION)
{
        set_kb_item(name:"GSHB-11/M5_123/result", value:"nicht zutreffend");
        set_kb_item(name:"GSHB-11/M5_123/desc", value:"Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!");
        set_kb_item(name:"GSHB-11/M5_123/name", value:name);
    log_message(port:0, proto: "IT-Grundschutz", data:string("Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!"));  
    exit(0);
}


gshbm =  "IT-Grundschutz M5.123: ";
CPSGENERAL = get_kb_item("WMI/cps/GENERAL");
log = get_kb_item("WMI/cps/GENERAL/log");
OSVER = get_kb_item("WMI/WMI_OSVER");
OSNAME = get_kb_item("WMI/WMI_OSNAME");
WMIOSLOG = get_kb_item("WMI/WMI_OS/log");
disablepasswordchange = get_kb_item("WMI/cps/disablepasswordchange");
maximumComppasswordage = get_kb_item("WMI/cps/maximumComppasswordage");
requirestrongkey = get_kb_item("WMI/cps/requirestrongkey");
requiresignorseal = get_kb_item("WMI/cps/requiresignorseal");
sealsecurechannel = get_kb_item("WMI/cps/sealsecurechannel");
signsecurechannel = get_kb_item("WMI/cps/signsecurechannel");
RequireSecuritySignatureWs = get_kb_item("WMI/cps/RequireSecuritySignatureWs");
EnableSecuritySignatureWs = get_kb_item("WMI/cps/EnableSecuritySignatureWs");
EnablePlainTextPassword = get_kb_item("WMI/cps/EnablePlainTextPassword");
NTLMMinClientSec = get_kb_item("WMI/cps/NTLMMinClientSec");
LMCompatibilityLevel = get_kb_item("WMI/scp/LMCompatibilityLevel");
NoLMHash = get_kb_item("WMI/cps/NoLMHash");
LSAAnonymousNameLookup = get_kb_item("WMI/cps/LSAAnonymousNameLookup");
if (LSAAnonymousNameLookup != "None")
{
  LSAAnonymousNameLookup = split(LSAAnonymousNameLookup, sep:'\n', keep:0);
  LSAAnonymousNameLookup = split(LSAAnonymousNameLookup[1], sep:'|', keep:0);
  LSAAnonymousNameLookup = LSAAnonymousNameLookup[2];
}
RestrictAnonymousSAM = get_kb_item("WMI/cps/RestrictAnonymousSAM");
RestrictAnonymous = get_kb_item("WMI/cps/RestrictAnonymous");
EveryoneIncludesAnonymous = get_kb_item("WMI/cps/EveryoneIncludesAnonymous");

if (WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System."){
  result = string("nicht zutreffend");
  desc = string("Auf dem System läuft Samba, es ist kein Microsoft System.");
}else if("error" >< CPSGENERAL){
  result = string("Fehler");
  if (!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
  if (log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
}else if(!CPSGENERAL){
  result = string("Fehler");
  desc = string("Beim Testen des Systems trat ein Fehler auf.\nEs konnte keine RSOP Abfrage durchgeführt werden.");
}else if(( OSVER == '5.2' && OSNAME >!< 'Microsoft(R) Windows(R) XP Professional x64 Edition') || (OSVER == '6.0' && OSTYPE > 1) || (OSVER == '6.1' && OSTYPE > 1)){
  result = string("nicht zutreffend");
  desc = string("Das System ist kein Windows-Clientbetriebssystem.");
}else if(disablepasswordchange == "0" && maximumComppasswordage >= "30" && requirestrongkey == "1" && requiresignorseal == "1" && sealsecurechannel == "1" && signsecurechannel == "1" && RequireSecuritySignatureWs == "1" && EnableSecuritySignatureWs == "1" && EnablePlainTextPassword == "0" && NTLMMinClientSec == "537395248" && LMCompatibilityLevel >= "4" && NoLMHash == "1" && LSAAnonymousNameLookup == "False" && RestrictAnonymous == "1" && RestrictAnonymousSAM == "1" && EveryoneIncludesAnonymous == "0")
{
  result = string("erfüllt");
  desc = string("Die Sicherheitseinstellungen stimmen mit der\nMaßnahme M5.123 überein.");
}else{
  result = string("nicht erfüllt");
  if (disablepasswordchange != "0") val = val + '\n' + "disablepasswordchange: " + disablepasswordchange;
  if (maximumComppasswordage < "30") val = val + '\n' + "maximumComppasswordage: " + maximumComppasswordage;
  if (requirestrongkey != "1") val = val + '\n' + "requirestrongkey: " + requirestrongkey;
  if (requiresignorseal != "1") val = val + '\n' + "requiresignorseal: " + requiresignorseal;
  if (sealsecurechannel != "1") val = val + '\n' + "sealsecurechannel: " + sealsecurechannel;
  if (signsecurechannel != "1") val = val + '\n' + "signsecurechannel: " + signsecurechannel;
  if (RequireSecuritySignatureWs != "1") val = val + '\n' + "RequireSecuritySignatureWs: " + RequireSecuritySignatureWs;
  if (EnableSecuritySignatureWs != "1") val = val + '\n' + "EnableSecuritySignatureWs: " + EnableSecuritySignatureWs;
  if (EnablePlainTextPassword != "0") val = val + '\n' + "EnablePlainTextPassword: " + EnablePlainTextPassword;
  if (NTLMMinClientSec != "537395248") val = val + '\n' + "NTLMMinClientSec: " + NTLMMinClientSec;
  if (LMCompatibilityLevel < "4") val = val + '\n' + "LMCompatibilityLevel: " + LMCompatibilityLevel;
  if (NoLMHash != "1") val = val + '\n' + "NoLMHash: " + NoLMHash;
  if (LSAAnonymousNameLookup != "False") val = val + '\n' + "LSAAnonymousNameLookup: " + LSAAnonymousNameLookup;
  if (RestrictAnonymous != "1") val = val + '\n' + "RestrictAnonymous: " + RestrictAnonymous;
  if (RestrictAnonymousSAM != "1") val = val + '\n' + "RestrictAnonymousSAM: " + RestrictAnonymousSAM;
  if (EveryoneIncludesAnonymous != "0") val = val + '\n' + "EveryoneIncludesAnonymous: " + EveryoneIncludesAnonymous;
  desc = string("Die Sicherheitseinstellungen stimmen nicht mit der Maßnahme\nM5.123 überein. Folgende Einstellungen sind nicht wie gefordert\numgesetzt:\n" + val);
}

set_kb_item(name:"GSHB-11/M5_123/result", value:result);
set_kb_item(name:"GSHB-11/M5_123/desc", value:desc);
set_kb_item(name:"GSHB-11/M5_123/name", value:name);


silence = get_kb_item("GSHB-11/silence");

if (silence){
exit(0);
} else {
  report = 'Ergebnisse zum IT-Grundschutz, 11. Ergänzungslieferung:\n\n';
  report = report + name + 'Ergebnis:\t' + result +
           '\nDetails:\t' + desc + '\n\n';
    if ("nicht erfüllt" >< result || result >< "Fehler"){
    security_hole(port:0, proto: "IT-Grundschutz", data:report);
    } else if (result >< "unvollständig"){
    security_warning(port:0, proto: "IT-Grundschutz", data:report);
    } else if (result >< "erfüllt" || result >< "nicht zutreffend"){
    security_note(port:0, proto: "IT-Grundschutz", data:report);
    }
exit(0);
}
