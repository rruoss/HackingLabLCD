###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M5_072.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 11. EL, Maﬂnahme 5.072
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
tag_summary = "IT-Grundschutz M5.072: Deaktivieren nicht benˆtigter Netzdienste.

  Diese Pr¸fung bezieht sich auf die 11. Erg‰nzungslieferung (11. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
  Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

  Hinweis:

  Lediglich Anzeige der in Frage kommenden Dienste.

  http://www.bsi.bund.de/grundschutz/kataloge/m/m05/m05072.html";


if(description)
{
  script_id(895072);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Tue Mar 09 16:24:41 2010 +0100");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M5.072: Deaktivieren nicht benˆtigter Netzdienste");
  if (! OPENVAS_VERSION)
  {
    desc = "
    Leider setzen Sie einen zu alten OpenVAS Scan-Server ein.
    Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!";
    script_description(desc);
    script_summary("IT-Grundschutz M5.072: Deaktivieren nicht benˆtigter Netzdienste.");
    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
    script_family("IT-Grundschutz-11");
    exit(0);
  }
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("IT-Grundschutz M5.072: Deaktivieren nicht benˆtigter Netzdienste.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-11");
  script_mandatory_keys("Compliance/Launch/GSHB-11");
  script_dependencies("GSHB/GSHB_SLAD_Netstat_natcp.nasl", "GSHB/GSHB_SSH_netstat.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


name = 'IT-Grundschutz M5.072: Deaktivieren nicht benˆtigter Netzdienste\n';

if (! OPENVAS_VERSION)
{
        set_kb_item(name:"GSHB-11/M5_072/result", value:"nicht zutreffend");
        set_kb_item(name:"GSHB-11/M5_072/desc", value:"Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!");
        set_kb_item(name:"GSHB-11/M5_072/name", value:name);
    log_message(port:0, proto: "IT-Grundschutz", data:string("Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!"));  
    exit(0);
}


gshbm =  "GSHB Maﬂnahme 5.072: ";

SLADNetstat = get_kb_item("GSHB/SLAD/NETSTAT");
log = get_kb_item("GSHB/SLAD/NETSTAT/log");
SSHNetstat = get_kb_item("GSHB/SSH/NETSTAT");

if(SLADNetstat >< "nosock" && SSHNetstat >< "nosock"){
  result = string("Fehler");
   desc = string('Beim Testen des Systems wurde festgestellt, dass keine\nSSH Verbindung aufgebaut werden konnte. Das kˆnnte daran\nliegen, dass WinSLAD auf dem Ziel nicht installiert ist.\nWinSLAD wird benˆtigt um diesen Test auszuf¸hren. Dabei wird\nauch der nˆtige SSH-Zugang zum System mit installiert.');
}else if ((SLADNetstat >< "nosock" || "noslad" >< SLADNetstat || SLADNetstat =~ "404 (P|p)lugin not found.*") && SSHNetstat >!< "nosock"){
  if (SSHNetstat >!< "none"){
    result = string("unvollst‰ndig");
    desc = string('Bitte pr¸fen Sie das Ergebnis und deaktivieren ggf. nicht\nbenˆtigter Netzdienste:\n\n' + SSHNetstat);
  }else if (SSHNetstat >< "none"){
    result = string("Fehler");
    desc = string('Es konnte ¸ber "netstat" kein Ergebnis ermittelt werden.');
  }  
}else if (SLADNetstat >!< "nosock"){
  if(SLADNetstat >< "none"){
    result = string("Fehler");
    desc = string('Beim Testen des Systems wurde festgestellt,\ndass SLAD keine Ergebnisse geliefert hat.');
  }else if(SLADNetstat =~ "404 (P|p)lugin not found.*"){
    result = string("Fehler");
    desc = string('Beim Testen des Systems wurde festgestellt, dass das notwendige\nSLAD Plugin "Netstat" nicht installiert ist.');
  }else if(SLADNetstat >< "running"){
    result = string("unvollst‰ndig");
    desc = string('Beim Testen des Systems wurde festgestellt, dass SLAD nocht\nnicht mit allen Tests fertig ist.\nBitte wiederholen Sie den\nTest sp‰ter noch einmal.');
  }else if("noslad" >< SLADNetstat) {
    result = string("Fehler");
    desc = string('Anscheinend ist SLAD nicht installiert\noder falsch konfiguriert.');
  }else{
    result = string("unvollst‰ndig");
    desc = string('Bitte pr¸fen Sie das Ergebnis, und deaktivieren ggf.\nnicht benˆtigter Netzdienste:\n\n' + SLADNetstat);
  }
}

if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler auf\nbzw. es konnte kein Ergebnis ermittelt werden.'); 
}

set_kb_item(name:"GSHB-11/M5_072/result", value:result);
set_kb_item(name:"GSHB-11/M5_072/desc", value:desc);
set_kb_item(name:"GSHB-11/M5_072/name", value:name);

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
