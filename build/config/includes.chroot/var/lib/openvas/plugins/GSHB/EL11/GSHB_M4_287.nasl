###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_287.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 11. EL, Maﬂnahme 4.287
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
tag_summary = "IT-Grundschutz M4.287: Sichere Administration der VoIP-Middleware.

  Diese Pr¸fung bezieht sich auf die 11. Erg‰nzungslieferung (11. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
  Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

  http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04287.html";

if(description)
{
  script_id(894287);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Tue Jun 01 15:07:45 2010 +0200");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.287: Sichere Administration der VoIP-Middleware");
  
  if (! OPENVAS_VERSION)
  {
    desc = "Leider setzen Sie einen zu alte OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!";
    script_description(desc);
    script_summary("IT-Grundschutz M4.287: Sichere Administration der VoIP-Middleware.");
    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
    script_family("IT-Grundschutz-11");
    exit(0);
  }
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("IT-Grundschutz M4.287: Sichere Administration der VoIP-Middleware.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-11");
  script_mandatory_keys("Compliance/Launch/GSHB-11");
  script_dependencies("find_service.nasl","sip_detection.nasl","ssh_proto_version.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.287: Sichere Administration der VoIP-Middleware\n';



if (! OPENVAS_VERSION)
  {
        set_kb_item(name:"GSHB-11/M4_287/result", value:"nicht zutreffend");
        set_kb_item(name:"GSHB-11/M4_287/desc", value:"Leider setzen Sie einen zu alte OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!");
        set_kb_item(name:"GSHB-11/M4_287/name", value:name);
    log_message(port:0, proto: "IT-Grundschutz", data:string("Leider setzen Sie einen zu alte OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!"));  
    exit(0);
}

gshbm =  "IT-Grundschutz M4.287: ";

sip = get_kb_item("Services/udp/sip");
sshver = get_kb_item("SSH/supportedversions/22");
http = http_open_socket(80);

Lst = split(sshver, sep:",", keep:0);
for(i=0; i<max_index(Lst); i++){  
  if (Lst[i] =~ " 2.0:.*") continue;
  if (Lst[i] =~ " 1.99:.*") continue;
  if (Lst[i] =~ " 1.*:.*") val += Lst[i] + ",";
}

if(!sip){
    result = string("nicht zutreffend");
    desc = string('Auf dem Zielsystem wurde kein SIP-Dienst gefunden.\nDavon ausgehend, wird es nicht als VoIP-Middleware\nbehandelt.');
}else if (!http && !val){
    result = string("erf¸llt");
    if (!http && !val) desc = string('Auf dem Zielsystem wurde weder ein HTTP-Server-Port\n80 noch die SSH-Protokollversion 1 gefunden.');
    else if (!http) desc = string('Auf dem Zielsystem wurde kein HTTP-Server-\nPort 80 gefunden.');
    else if (!val) desc = string('Auf dem Zielsystem wurde die SSH-Protokollversion 1\nnicht gefunden.');
}else {
    result = string("nicht erf¸llt");
    if (http && val) desc = string('Auf dem Zielsystem wurde ein HTTP-Server-Port 80 und\ndie SSH-Protokollversion 1 gefunden. Eine Web-basierte\nKonfiguration sollte immer gesichert erfolgen,\nbeispielsweise durch den Einsatz von SSL oder TLS.\nIhre SSH Einstellungen lassen Verbindungen mit der\nProtokollversion 1 zu. Diese Version enth‰lt Schwach-\nstellen. Sie sollten nur die Protokollversion 2\neinsetzten.');
    else if (!http) desc = string('Auf dem Zielsystem wurde ein HTTP-Server-Port 80\ngefunden. Eine Web-basierte Konfiguration sollte immer\ngesichert erfolgen, beispielsweise durch den Einsatz\nvon SSL oder TLS.');
    else if (!val) desc = string('Auf dem Zielsystem wurde die SSH-Protokollversion 1\ngefunden. Ihre SSH Einstellungen lassen Verbindungen\nmit der Protokollversion 1 zu. Diese Version enth‰lt\nSchwachstellen. Sie sollten nur die Protokollversion 2\neinsetzten.');
}

if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler\nauf bzw. es konnte kein Ergebnis ermittelt werden.'); 
}

if(http) close(http);
  
set_kb_item(name:"GSHB-11/M4_287/result", value:result);
set_kb_item(name:"GSHB-11/M4_287/desc", value:desc);
set_kb_item(name:"GSHB-11/M4_287/name", value:name);

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

