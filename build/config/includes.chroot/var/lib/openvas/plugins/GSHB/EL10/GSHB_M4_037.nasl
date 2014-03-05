###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_037.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 10. EL, Maﬂnahme 4.037
#
# Authors:
# Thomas Rotter <T.Rotter@dn-systems.de>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "IT-Grundschutz M4.037: Sperren bestimmter Absender-Faxnummern.

  Diese Pr¸fung bezieht sich auf die 10. Erg‰nzungslieferung (10. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
  Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

  http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04037.html";

if(description)
{
  script_id(94037);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Thu Jun 10 15:20:25 2010 +0200");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.037: Sperren bestimmter Absender-Faxnummern");
  
  if (! OPENVAS_VERSION)
  {
    desc = "Leider setzen Sie einen zu alte OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!";
    script_description(desc);
    script_summary("IT-Grundschutz M4.037: Sperren bestimmter Absender-Faxnummern.");
    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
    script_family("IT-Grundschutz-10");
    exit(0);
  }
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("IT-Grundschutz M4.037: Sperren bestimmter Absender-Faxnummern.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-10");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-10");
  script_dependencies("GSHB/GSHB_TELNET_Cisco_Voice.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.037: Sperren bestimmter Absender-Faxnummern\n';



if (! OPENVAS_VERSION)
  {
        set_kb_item(name:"GSHB-10/M4_037/result", value:"nicht zutreffend");
        set_kb_item(name:"GSHB-10/M4_037/desc", value:"Leider setzen Sie einen zu alte OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!");
        set_kb_item(name:"GSHB-10/M4_037/name", value:name);
    log_message(port:0, proto: "IT-Grundschutz", data:string("Leider setzen Sie einen zu alte OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!"));  
    exit(0);
}

gshbm =  "IT-Grundschutz M4.037: ";

ciscovoice = get_kb_item("GSHB/Voice");
log = get_kb_item("GSHB/Voice/log");
translation = get_kb_item("GSHB/Voice/translation");

if (log == "no Telnet Port"){
  result = string("nicht zutreffend");
  desc = string('Beim Testen des Systems wurde kein Telnet-Port gefunden.'); 
}else if (ciscovoice == "no credentials set"){
  result = string("unvollst‰ndig");
  desc = string('Um diesen Test durchzuf¸hren, muss ihn in den Voreinstellungen unter:\n-IT-Grundschutz: List reject Rule on Cisco Voip Devices over Telnet-\nein Benutzername und Passwort eingetragen werden.'); 
}else if (ciscovoice == "Login Failed"){
  result = string("Fehler");
  desc = string('Es war nicht mˆglich sich am Zielsystem anzumelden.'); 
}else if (ciscovoice == "nocisco"){
  result = string("nicht zutreffend");
  desc = string('Das Ziel konnt nicht als Cisco-Ger‰t erkannt werden.'); 
}else if (ciscovoice == "novoice"){
  result = string("nicht zutreffend");
  desc = string('Das Ziel konnt als Cisco-Ger‰t erkannt werden. Allerdings konnte keine Voice-Funktion erkannt werden.'); 
}else if (translation == "noconfig"){
  result = string("nicht erf¸llt");
  desc = string('Auf dem Cisco-Ger‰t wurde Voip Funktionalit‰ten entdeckt. Allerdings konnte keine -translation-rule- nacht dem Muster - rule .* reject .*-  entdeckt werden.'); 
}else if (translation != "noconfig"){
  result = string("unvollst‰ndig");
  desc = string('Auf dem Cisco-Ger‰t wurde Voip Funktionalit‰ten entdeckt. Es wurden folgende -translation-rule- gefunden:\n' + translation +'Bitte Pr¸fen Sie ob alle ggf. zu sperrenden Absender-Faxnummern eingetragen sind.');
}

if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler auf bzw. es konnte kein Ergebnis ermittelt werden.'); 
}


set_kb_item(name:"GSHB-10/M4_037/result", value:result);
set_kb_item(name:"GSHB-10/M4_037/desc", value:desc);
set_kb_item(name:"GSHB-10/M4_037/name", value:name);

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
