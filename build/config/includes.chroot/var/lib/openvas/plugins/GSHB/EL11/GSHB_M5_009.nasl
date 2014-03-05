###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M5_009.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 11. EL, Maﬂnahme 5.009
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
tag_summary = "IT-Grundschutz M5.009: Protokollierung am Server.

  Diese Pr¸fung bezieht sich auf die 11. Erg‰nzungslieferung (11. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
  Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

  http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m05009.html";

if(description)
{
  script_id(895009);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Thu Apr 29 13:54:01 2010 +0200");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M5.009: Protokollierung am Server");
  script_add_preference(name:"Alle Logfile-Eintr‰ge Auflisten", type:"checkbox", value:"no");
  
  if (! OPENVAS_VERSION)
  {
    desc = "Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers.";
    script_description(desc);
    script_summary("IT-Grundschutz M5.009: Protokollierung am Server");
    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
    script_family("IT-Grundschutz-11");
    exit(0);
  }
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("IT-Grundschutz M5.009: Protokollierung am Server.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-11");
  script_mandatory_keys("Compliance/Launch/GSHB-11");
  script_dependencies ("GSHB/GSHB_SLAD_logwatchlow.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M5.009: Protokollierung am Server\n';



if (! OPENVAS_VERSION)
  {
        set_kb_item(name:"GSHB-11/M5_009/result", value:"nicht zutreffend");
        set_kb_item(name:"GSHB-11/M5_009/desc", value:"Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers.");
        set_kb_item(name:"GSHB-11/M5_009/name", value:name);
    log_message(port:0, proto: "IT-Grundschutz", data:string("Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers."));  
    exit(0);
}

gshbm =  "IT-Grundschutz M5.009: ";

verbose = script_get_preference("Alle Logfile-Eintr‰ge Auflisten");
OSTYPE = get_kb_item("WMI/WMI_OSTYPE");
OSVER = get_kb_item("WMI/WMI_OSVER");
OSNAME = get_kb_item("WMI/WMI_OSNAME");
WINLOG = get_kb_item("WMI/WMI_OS/log");
WMIOSLOG = get_kb_item("WMI/WMI_OS/log");
logwatch = get_kb_item("GSHB/SLAD/LOGWATCH");
loglenght = get_kb_item("GSHB/SLAD/LOGLENGHT");
log = get_kb_item("GSHB/SLAD/LOGWATCH/log");

if (OSNAME >!< "none"){
  if(!OSNAME){
    result = string("Fehler");
    if (!WINLOG) desc = string("Beim Testen des Systems trat ein Fehler auf.");
    if (WINLOG) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
  }else if (OSTYPE == "1" || (OSTYPE == "none" && OSVER == "5.1")){
    result = string("nicht zutreffend");
    desc = string("Das System ist ein Windows-Clientbetriebssystem.");  
  }else{
    result = string("unvollst‰ndig");
    desc = string("Das System ist ein Windows-Serverbetriebssystem und\nkann zur Zeit noch nicht getestet werden.");  
  }
}else{
  if(logwatch >< "nosock"){
    result = string("Fehler");
   if (!log) desc = string('Beim Testen des Systems wurde festgestellt, dass keine\nSSH Verbindung aufgebaut werden konnte.');
   if (log) desc = string("Beim Testen des Systems trat beim Verbinden ¸ber SSH\nein Fehler auf:\n" + log);
  }else if(logwatch >< "none"){
    result = string("Fehler");
    desc = string('Beim Testen des Systems wurde festgestellt,\ndass SLAD keine Ergebnisse geliefert hat.');
  }else if(logwatch =~ "404 (P|p)lugin not found.*"){
    result = string("Fehler");
    desc = string('Beim Testen des Systems wurde festgestellt, dass das\nnotwendige logwatch Plugin nicht installiert ist.');
  }else if(logwatch >< "running"){
  result = string("unvollst‰ndig");
  desc = string('Beim Testen des Systems wurde festgestellt, dass SLAD\nnocht nicht fertig ist.\nBitte wiederholen Sie den\nTest sp‰ter noch einmal.');
  }else if(logwatch >< "noslad") {
  result = string("Fehler");
  desc = string('Anscheinend ist SLAD nicht installiert oder falsch\nkonfiguriert.');
}else{
  result = string("unvollst‰ndig");
  if (verbose == "yes")desc = string('Pr¸fen Sie die Eintr‰ge im nachfolgenden Logfile:\n' + logwatch);
#  if (verbose == "yes" || (verbose != "yes"  && loglenght <= 2000))desc = string('Pr¸fen Sie die Eintr‰ge im nachfolgenden Logfile:\n' + logwatch);  
  else desc = string('Das Logfile ist ' + loglenght + ' Zeichen lang. F¸r eine\nvollst‰ndige Liste, w‰hlen Sie bei den Voreinstel-\nlungen dieses Tests: Alle Logfile-Eintr‰ge Auflisten');
  }
}
if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler\nauf bzw. es konnte kein Ergebnis ermittelt werden.'); 
}

set_kb_item(name:"GSHB-11/M5_009/result", value:result);
set_kb_item(name:"GSHB-11/M5_009/desc", value:desc);
set_kb_item(name:"GSHB-11/M5_009/name", value:name);

silence = get_kb_item("GSHB-11/silence");

if (silence){
exit(0);
} else {
  report = 'Ergebnisse zum IT-Grundschutz, 11. Erg‰nzungslieferung:\n\n';
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
