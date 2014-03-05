###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_093.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 12. EL, Maßnahme 4.093
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
tag_summary = "IT-Grundschutz M4.093: Regelmäßige Integritätsprüfung

Diese Prüfung bezieht sich auf die 12. Ergänzungslieferung (12. EL) des IT-
Grundschutz. Die detaillierte Beschreibung zu dieser Maßnahme findet sich unter
nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
die aktuellste Ergänzungslieferung bezieht. Titel und Inhalt können sich bei einer
Aktualisierung ändern, allerdings nicht die Kernthematik.

http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04093.html";

if(description)
{
  script_id(94054);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2011-11-07 13:38:53 +0100 (Mon, 07 Nov 2011)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.093: Regelmäßige Integritätsprüfung");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("IT-Grundschutz M4.093: Regelmäßige Integritätsprüfung");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-12");
  script_mandatory_keys("Compliance/Launch/GSHB-12");
  script_dependencies ("find_service.nasl", "ssh_authorization.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.093: Regelmäßige Integritätsprüfungn\n';

gshbm =  "IT-Grundschutz M4.093: ";

include ("ssh_func.inc");
include ("slad.inc");

OSNAME = get_kb_item("WMI/WMI_OSNAME");

sock = ssh_login_or_reuse_connection();
if(!sock)  ssh = get_ssh_error();
else ssh = "ok";

sladlst = ssh_cmd (socket: sock, cmd: "/opt/slad/bin/sladd -s plugins", timeout: 120);
if (sladlst =~ ".*Datei oder Verzeichnis nicht gefunden.*" ||  sladlst =~ ".*No such file or directory.*") sladlst = "noslad";
else if (!sladlst)  sladlst = "none";

if (sladlst != "noslad" && sladlst != "none"){
  Lst = split(sladlst, keep:0);
  for(i=0; i<max_index(Lst); i++){  
    if (Lst[i] =~ "p:tripwire.*") tripwire = "yes";
    if (Lst[i] =~ "p:tiger.*") tiger = "yes";
  }
}

if (!tripwire) tripwire = "no";
if (!tiger) tiger = "no";

if(OSNAME >!< "none"){
  result = string("unvollständig");
  desc = string('Folgendes System wurde erkannt:\n' + OSNAME + '\nZur Zeit gibt es die Slad-Plugins Tiger und Tripwire\nnicht für Windows Systeme.');
}else if (ssh != "ok"){
  result = string("Fehler");
  desc = string('Um das System mit SLAD zu Testen, benötigen Sie eine\nSSH Verbindung. Folgender Fehler ist aufgetreten:\n' + ssh);
}else if (sladlst == "noslad"){
  result = string("Fehler");
  desc = string('Auf dem System ist SLAD nicht installiert. Demnach\nkann das System nicht gemäß Maßnahme 4.093\ngetestet werden.');
}else if (sladlst != "noslad" && (tripwire == "no" || tiger == "no")){
  result = string("Fehler");
  desc = string('Auf dem System fehlen folgende Slad Plugins:\n');
  if (tripwire == "no")desc += string(' -tripwire-');
  if (tiger == "no")desc += string(' -tiger-');
  desc += string('\nDemnach kann das System nicht gemäß Maßnahme 4.093\ngetestet werden.');
}else{
  result = string("unvollständig");
  desc = string('Auf dem System ist Slad mit den Slad Plugins Tiger und\nTripwire installiert. Führen Sie bitte eine \nOpenVAS-Prüfung Ihres Netzwerkes mit den genannten\nSLAD Plugins aus.');
}

if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler\nauf bzw. es konnte kein Ergebnis ermittelt werden.'); 
}

if (sock)close (sock);

set_kb_item(name:"GSHB-12/M4_093/result", value:result);
set_kb_item(name:"GSHB-12/M4_093/desc", value:desc);
set_kb_item(name:"GSHB-12/M4_093/name", value:name);

silence = get_kb_item("GSHB-12/silence");

if (silence){
exit(0);
} else {
  report = 'Ergebnisse zum IT-Grundschutz, 12. Ergänzungslieferung:\n\n';
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
