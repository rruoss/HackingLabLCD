###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_048.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 12. EL, Ma�nahme 4.048
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
tag_summary = "IT-Grundschutz M4.048: Passwortschutz unter NT-basierten Windows-Systemen (Win).

Diese Pr�fung bezieht sich auf die 12. Erg�nzungslieferung (12. EL) des IT-
Grundschutz. Die detaillierte Beschreibung zu dieser Ma�nahme findet sich unter
nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
die aktuellste Erg�nzungslieferung bezieht. Titel und Inhalt k�nnen sich bei einer
Aktualisierung �ndern, allerdings nicht die Kernthematik.

http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04048.html";


if(description)
{
  script_id(94045);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2011-11-07 13:38:53 +0100 (Mon, 07 Nov 2011)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.048: Passwortschutz unter NT-basierten Windows-Systemen (Win)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("IT-Grundschutz M4.048: Passwortschutz unter NT-basierten Windows-Systemen (Win).");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-12");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-12");
  script_dependencies("GSHB/GSHB_WMI_PasswdPolicie.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.048: Passwortschutz unter NT-basierten Windows-Systemen(Win)\n';

gshbm =  "IT-Grundschutz M4.048: ";

OSVER = get_kb_item("WMI/WMI_OSVER");
WMIOSLOG = get_kb_item("WMI/WMI_OS/log");

PP = get_kb_item("WMI/passwdpolicy");
LP = get_kb_item("WMI/lockoutpolicy");

PPS = get_kb_item("WMI/lockoutpolicy/stat");
LPS = get_kb_item("WMI/passwdpolicy/stat");

MINPA = get_kb_item("WMI/passwdpolicy/MinimumPasswordAge");
PHS = get_kb_item("WMI/passwdpolicy/PasswordHistorySize");
PHS = int(PHS);
LD = get_kb_item("WMI/passwdpolicy/LockoutDuration");
RLC = get_kb_item("WMI/passwdpolicy/ResetLockoutCount");
MPL = get_kb_item("WMI/passwdpolicy/MinimumPasswordLength");
LBC = get_kb_item("WMI/passwdpolicy/LockoutBadCount");
MAXPA = get_kb_item("WMI/passwdpolicy/MaximumPasswordAge");
RLTCP = get_kb_item("WMI/lockoutpolicy/RequireLogonToChangePassword");
PC = get_kb_item("WMI/lockoutpolicy/PasswordComplexity");
FLWHE = get_kb_item("WMI/lockoutpolicy/ForceLogoffWhenHourExpire");
CTP = get_kb_item("WMI/lockoutpolicy/ClearTextPassword");

log = get_kb_item("WMI/passwdpolicy/log");

if (WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System."){
  result = string("nicht zutreffend");
  desc = string("Auf dem System l�uft Samba, es ist kein\nMicrosoft Windows System.");
}else if(!OSVER){
  result = string("Fehler");
  desc = string("Beim Testen des Systems trat ein Fehler auf.");
}else if(!PPS || !LPS){
  result = string("Fehler");
  desc = string("Beim Testen des Systems trat ein Fehler auf.");
  if (!PPS)desc += string("\nDie Passwordpolicy konnte nicht ermittelt werden.");
  if (!LPS)desc += string("\nDie Lockoutpolicy konnte nicht ermittelt werden.");
}else if("error" >< PP || "error" >< LP){
  result = string("Fehler");
  if (!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
  if (log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
}else if(MINPA >= 1 && PHS >= 6 && LD >= 60 && RLC >= 30 && MPL >= 8 && LBC <= 3 && MAXPA <= 90 && RLTCP >< "False" && PC >< "True" && CTP >< "False"){
  result = string("erf�llt");
  desc = string("Die Kennwortrichtlinien und Kontosperrungsrichtlinien\nentsprechen der IT-Grundschutz Ma�nahme 4.048.");
}else{
  result = string("nicht erf�llt");
  desc = string("Die Kennwortrichtlinien und Kontosperrungsrichtlinien\nentsprechen nicht der IT-Grundschutz Ma�nahme 4.048.\n");
  if (LP >!< "False")
  {
    if (MINPA < 1)desc = desc + string("Das minimale Kennwortalter ist: " + MINPA + '\n');
    if (PHS < 6)desc = desc + string("Die Kennwortchronik umfasst nur " + PHS + ' Kennw�rter\n');
    if (LD < 60)desc = desc + string("Die Kontosperrdauer betr�gt nur " + LD + ' Minuten\n');
    if (RLC < 30)desc = desc + string("Die Zur�cksetzungsdauer des Kontosperrungsz�hlers\nbetr�gt nur " + RLC + ' Minuten\n');
    if (MPL < 8)desc = desc + string("Die minimale Kennwortl�nge betr�gt nur: " + MPL + '\n');
    if (LBC > 3)desc = desc + string("Die Kontosperrungsschwelle betr�gt " + LBC + '\nVersuche\n');
    if (MAXPA > 90)desc = desc + string("Das maximale Kennwortalter betr�gt nur " + MAXPA + '\nTage\n');
  }
  if (PP >!< "False")
  {
    if (RLTCP >< "True")desc = desc + string('-Benutzer muss sich anmelden, um Kennwort zu �ndern-\nist gesetzt\n');
    if (PC >< "False")desc = desc + string('-Kennwort muss Komplexittsvoraussetzungen entsprechen-\nist nicht gesetzt\n');
    if (CTP >< "True")desc = desc + string('-Kennw�rter f�r alle Dom�nenbenutzer mit umkehrbarer\nVerschl�sselung speichern- ist gesetzt\n');
  }
}

set_kb_item(name:"GSHB-12/M4_048/result", value:result);
set_kb_item(name:"GSHB-12/M4_048/desc", value:desc);
set_kb_item(name:"GSHB-12/M4_048/name", value:name);

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