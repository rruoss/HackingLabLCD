###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_016.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 12. EL, Maﬂnahme 4.016
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
tag_summary = "IT-Grundschutz M4.016: Zugangsbeschr‰nkungen f¸r Accounts und oder Terminals.

Diese Pr¸fung bezieht sich auf die 12. Erg‰nzungslieferung (12. EL) des IT-
Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04016.html";

if(description)
{
  script_id(94028);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2011-11-07 13:38:53 +0100 (Mon, 07 Nov 2011)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.016: Zugangsbeschr‰nkungen f¸r Accounts und oder Terminals");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("IT-Grundschutz M4.016: Zugangsbeschr‰nkungen f¸r Accounts und oder Terminals.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-12");
  script_mandatory_keys("Compliance/Launch/GSHB-12");
  script_dependencies("GSHB/GSHB_SSH_timerestriction.nasl", "GSHB/GSHB_WMI_OSInfo.nasl", "GSHB/GSHB_LDAP_User_w_LogonHours.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.016: Zugangsbeschr‰nkungen f¸r Accounts und oder Terminals\n';

gshbm =  "IT-Grundschutz M4.016: ";

LogonHours = get_kb_item("GSHB/LDAP_LogonHours");
log = get_kb_item("GSHB/LDAP_LogonHours/log");
timerest = get_kb_item("GSHB/timerest");
timerestlog = get_kb_item("GSHB/timerest/log");
OSNAME = get_kb_item("WMI/WMI_OSNAME");
WMIOSLOG = get_kb_item("WMI/WMI_OS/log");
WindowsDomainrole = get_kb_item("WMI/WMI_WindowsDomainrole");

if ((LogonHours >< "error" && WindowsDomainrole == "none") && timerest >< "error"){
  result = string("Fehler");
  if (!log && !timerestlog) desc = string("Beim Testen des Systems trat ein Fehler auf.");
  if (log || timerestlog){
    desc = string('Beim Testen des Systems trat ein Fehler auf:\n');
    if (log)desc += string('Windows WMI Fehler: '+log);
    if (timerestlog)desc += string('\nSSH Fehler: '+timerestlog);            
    }
}
else if(OSNAME >!< "none"){
  if (LogonHours != "none" && LogonHours != "error"){
      LogonHours_split = split(LogonHours, sep:'\n', keep:0);
      for(i=0; i<max_index(LogonHours_split); i++){  
        LogonUsers = split (LogonHours_split[i], sep:'|', keep:0);
        User += LogonUsers[0] + "; ";
      }
  }
  if(LogonHours >< "error" && (WindowsDomainrole == 4 || WindowsDomainrole == 5 || WindowsDomainrole == "none")){
    result = string("Fehler");
    if (!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
    if (log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
  }else if(LogonHours >< "error" && (WindowsDomainrole == "none" || WindowsDomainrole < 4)){
    result = string("nicht zutreffend");
    desc = string("Das System ist kein Windows Domaincontroller. Die\nKonfiguration der Domainuser kann nur an\nDomaincontrollern getestet werden.");
  }else if(LogonHours == "none"){
    result = string("nicht erf¸llt");
    desc = string('Es wurden keine Benutzer gefunden, die eine\nBeschr‰nkung in Ihrer Loginzeit haben!');
  }else if(User){
    result = string("unvollst‰ndig");
    desc = string('Es wurden Benutzer gefunden, die eine Beschr‰nkung in\nIhrer Loginzeit haben.\nBitte pr¸fen Sie, ob alle\nBenutzer aufgef¸hrt sind:\n' + User);
  } 
}else{
if(timerest == "windows") {
    result = string("Fehler");
    if (OSNAME >!< "none" && OSNAME >!< "error") desc = string('Folgendes System wurde erkannt:\n' + OSNAME + '\nAllerdings konnte auf das System nicht korrekt\nzugegriffen werden. Folgende Fehler sind aufgetreten:\n' + WMIOSLOG);
    else desc = string('Das System scheint ein Windows-System zu sein.\nAllerdings konnte auf das System nicht korrekt\nzugegriffen werden. Folgende Fehler sind aufgetreten:\n' + WMIOSLOG);
  }else if(timerest >< "error"){
    result = string("Fehler");
    if (!timerestlog)desc = string('Beim Testen des Systems trat ein\nunbekannter Fehler auf.');
    if (timerestlog)desc = string('Beim Testen des Systems trat ein Fehler auf:\n' + timerestlog);
  }else if(timerest >< "notfound"){
    result = string("unvollst‰ndig");
    desc = string('Die Datei /etc/security/time.conf wurde nicht gefunden\n. Bitte pr¸fen Sie ob die Beschr‰nkung der Loginzeiten\nauf eine andere Art konfiguriert ist.');
  }else if(timerest >< "none"){
    result = string("nicht erf¸llt");
    desc = string('Es konnten keine Eintr‰ge in /etc/security/time.conf\ngefunden werden.');
  }else if(timerest >!< "none"){
    result = string("erf¸llt");
    desc = string('Folgende Eintr‰ge wurden in /etc/security/time.conf\ngefunden:\n' + timerest + '\nBitte pr¸fen Sie, ob die Eintr‰ge vollst‰ndig sind!');
  }
}

set_kb_item(name:"GSHB-12/M4_016/result", value:result);
set_kb_item(name:"GSHB-12/M4_016/desc", value:desc);
set_kb_item(name:"GSHB-12/M4_016/name", value:name);

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
