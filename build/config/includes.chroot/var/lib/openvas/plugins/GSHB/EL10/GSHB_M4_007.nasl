###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_007.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 10. EL, Maﬂnahme 4.007
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
tag_summary = "IT-Grundschutz M4.007: ƒnderung voreingestellter Passwˆrter.

  Diese Pr¸fung bezieht sich auf die 10. Erg‰nzungslieferung (10. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
  Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

  http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04007.html";


if(description)
{
  script_id(94007);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Tue Jun 08 16:42:11 2010 +0200");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.007: ƒnderung voreingestellter Passwˆrter");
  if (! OPENVAS_VERSION)
  {
    desc = "
    Leider setzen Sie einen zu alten OpenVAS Scan-Server ein.
    Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!";
    script_description(desc);
    script_summary("IT-Grundschutz M4.007: ƒnderung voreingestellter Passwˆrter.");
    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
    script_family("IT-Grundschutz-10");
    exit(0);
  }
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("IT-Grundschutz M4.007: ƒnderung voreingestellter Passwˆrter.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-10");
  script_mandatory_keys("Compliance/Launch/GSHB-10");
  script_dependencies("GSHB/GSHB_SSH_TELNET_BruteForce.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


name = 'IT-Grundschutz M4.007: ƒnderung voreingestellter Passwˆrter\n';

if (! OPENVAS_VERSION)
{
        set_kb_item(name:"GSHB-10/M4_007/result", value:"nicht zutreffend");
        set_kb_item(name:"GSHB-10/M4_007/desc", value:"Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!");
        set_kb_item(name:"GSHB-10/M4_007/name", value:name);
    log_message(port:0, proto: "IT-Grundschutz", data:string("Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!"));  
    exit(0);
}


gshbm =  "IT-Grundschutz M4.007: ";

ssh = get_kb_item("GSHB/BRUTEFORCE/SSH"); 
telnet = get_kb_item("GSHB/BRUTEFORCE/TELNET");
winsmb = get_kb_item("GSHB/BRUTEFORCE/WINSMB");

if (ssh == "deactivated" && winsmb == "deactivated"){
  result = string("nicht zutreffend");
  desc = string('Der Test wurde nicht aktiviert. Um diesen Test auszuf¸hren,\nm¸ssen Sie ihn in den Voreinstellungen unter: -IT-Grundschutz: SSH and Telnet BruteForce attack-\nund/oder -IT-Grundschutz: Windows SMB BruteForce attack- aktivieren.'); 
}else if (ssh == "nossh" && telnet == "notelnet" && winsmb == "nowin"){
  result = string("Fehler");
  desc = string('Das System kann nicht getestet werden, da weder per SSH oder Telnet, noch per Windows SMB zugegriffen werden kann.'); 
}else if (ssh == "deactivated" && telnet == "deactivated" && winsmb == "nowin"){
  result = string("Fehler");
  desc = string('Das System kann nicht getestet werden, da per Windows SMB zugegriffen werden kann.\n‹ber SSH und Telnet wurde nicht getestet. Um diesen Test auszuf¸hren,\nm¸ssen Sie ihn in den Voreinstellungen unter: -IT-Grundschutz: SSH and Telnet BruteForce attack- aktivieren.'); 
}else if (ssh == "nossh" && telnet == "notelnet" && winsmb == "deactivated"){
  result = string("Fehler");
  desc = string('Das System kann nicht getestet werden, da weder per SSH noch per Telnet zugegriffen werden kann.\n‹ber Windows SMB wurde nicht getestet. Um diesen Test auszuf¸hren,\nm¸ssen Sie ihn in den Voreinstellungen unter: -IT-Grundschutz: Windows SMB BruteForce attack- aktivieren.'); 
}else if (ssh == "ok" && telnet == "ok" && winsmb == "ok"){
  result = string("erf¸llt");
  desc = string('Weder ¸ber SSH noch ¸ber Telnet konnte man sich mit einem Default-User und -Passwort anmelden.'); 
}


else if (ssh == "ok" && telnet == "ok" && winsmb == "deactivated") {
  result = string("erf¸llt");
  desc = string('Weder ¸ber SSH noch ¸ber Telnet konnte man sich mit einem Default-User und -Passwort anmelden.\n‹ber Windows SMB wurde nicht getestet. Um diesen Test auszuf¸hren,\nm¸ssen Sie ihn in den Voreinstellungen unter: -IT-Grundschutz: Windows SMB BruteForce attack- aktivieren.'); 
}


else if ((ssh == "ok" || ssh == "nossh") && telnet == "ok" && winsmb == "deactivated"){
  result = string("erf¸llt");
  desc = string('Weder ¸ber SSH noch ¸ber Telnet konnte man sich mit einem Default-User und -Passwort anmelden.\n‹ber Windows SMB wurde nicht getestet. Um diesen Test auszuf¸hren,\nm¸ssen Sie ihn in den Voreinstellungen unter: -IT-Grundschutz: Windows SMB BruteForce attack- aktivieren.'); 
}




else if (ssh == "ok" && (telnet == "ok" || telnet == "notelnet") && winsmb == "deactivated"){
  result = string("erf¸llt");
  desc = string('Weder ¸ber SSH noch ¸ber Telnet konnte man sich mit einem Default-User und -Passwort anmelden.\n‹ber Windows SMB wurde nicht getestet. Um diesen Test auszuf¸hren,\nm¸ssen Sie ihn in den Voreinstellungen unter: -IT-Grundschutz: Windows SMB BruteForce attack- aktivieren.'); 
}



else if (ssh == "deactivated" && telnet == "deactivated" && winsmb == "ok"){
  result = string("erf¸llt");
  desc = string('‹ber Windows SMB konnte man sich nicht mit einem Default-User und -Passwort anmelden.\n‹ber SSH und Telnet wurde nicht getestet. Um diesen Test auszuf¸hren,\nm¸ssen Sie ihn in den Voreinstellungen unter: -IT-Grundschutz: SSH and Telnet BruteForce attack- aktivieren.'); 
}else{
  result = string("nicht erf¸llt");
  if (ssh == "deactivated")desc = string('‹ber SSH und Telnet wurde nicht getestet. Um diesen Test auszuf¸hren,\nm¸ssen Sie ihn in den Voreinstellungen unter: -IT-Grundschutz: SSH and Telnet BruteForce attack- aktivieren.\n');
  if (winsmb == "deactivated")desc += string('‹ber Windows SMB wurde nicht getestet. Um diesen Test auszuf¸hren,\nm¸ssen Sie ihn in den Voreinstellungen unter: -IT-Grundschutz: Windows SMB BruteForce attack- aktivieren.\n'); 
  desc += string('Mit folgenden Daten konnte man sich am System anmelden:\n');
  if( ssh != "nossh" && ssh != "ok" && ssh != "deactivated")desc += string('SSH: ' + ssh + '\n');
  if( telnet != "notelnet" && telnet != "ok" && telnet != "deactivated")desc += string('Telnet: ' + telnet + '\n');
  if( winsmb != "nowin" && winsmb != "ok" && winsmb != "deactivated")desc += string('Windows SMB: ' + winsmb);
}

if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler auf bzw. es konnte kein Ergebnis ermittelt werden.'); 
}


set_kb_item(name:"GSHB-10/M4_007/result", value:result);
set_kb_item(name:"GSHB-10/M4_007/desc", value:desc);
set_kb_item(name:"GSHB-10/M4_007/name", value:name);

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
