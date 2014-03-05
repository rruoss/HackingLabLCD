###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_093.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 10. EL, Ma�nahme 4.093
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
tag_summary = "IT-Grundschutz M4.093: Regelm��ige Integrit�tspr�fung

  Diese Pr�fung bezieht sich auf die 10. Erg�nzungslieferung (10. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Ma�nahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Erg�nzungslieferung bezieht. Titel und Inhalt k�nnen sich bei einer
  Aktualisierung �ndern, allerdings nicht die Kernthematik.

  http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04093.html";

if(description)
{
  script_id(94093);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Wed Jun 02 10:43:31 2010 +0200");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.093: Regelm��ige Integrit�tspr�fung");
  
  if (! OPENVAS_VERSION)
  {
    desc = "Leider setzen Sie einen zu alte OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!";
    script_description(desc);
    script_summary("IT-Grundschutz M4.093: Regelm��ige Integrit�tspr�fung");
    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
    script_family("IT-Grundschutz-10");
    exit(0);
  }
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("IT-Grundschutz M4.093: Regelm��ige Integrit�tspr�fung");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-10");
  script_mandatory_keys("Compliance/Launch/GSHB-10");
  script_dependencies ("find_service.nasl", "ssh_authorization.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.093: Regelm��ige Integrit�tspr�fungn\n';



if (! OPENVAS_VERSION)
  {
        set_kb_item(name:"GSHB-10/M4_093/result", value:"nicht zutreffend");
        set_kb_item(name:"GSHB-10/M4_093/desc", value:"Leider setzen Sie einen zu alte OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!");
        set_kb_item(name:"GSHB-10/M4_093/name", value:name);
    log_message(port:0, proto: "IT-Grundschutz", data:string("Leider setzen Sie einen zu alte OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!"));  
    exit(0);
}

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
  result = string("unvollst�ndig");
  desc = string('Das System ist ein ' + OSNAME + ' System.\nZur Zeit gibt es die Slad-Plugins Tiger und Tripwire nicht f�r Windows Systeme.');
}else if (ssh != "ok"){
  result = string("Fehler");
  desc = string('Um das System mit SLAD zu Testen, ben�tigen Sie eine SSH Verbindung.\nFolgender Fehler ist aufgetreten:' + ssh);
}else if (sladlst == "noslad"){
  result = string("Fehler");
  desc = string('Auf dem System ist SLAD nicht installiert. Demnach kann das System nicht gem�� Ma�nahme 4.093 getestet werden.');
}else if (sladlst != "noslad" && (tripwire == "no" || tiger == "no")){
  result = string("Fehler");
  desc = string('Auf dem System fehlen folgende Slad Plugins:');
  if (tripwire == "no")desc += string(' -tripwire-');
  if (tiger == "no")desc += string(' -tiger-');
  desc += string('\nDemnach kann das System nicht gem�� Ma�nahme 4.093 getestet werden.');
}else{
  result = string("unvollst�ndig");
  desc = string('Auf dem System ist Slad mit den Slad Plugins Tiger und Tripwire installiert.\nF�hren Sie bitte eine OpenVAS-Pr�fung Ihres Netzwerkes mit den genannten SLAD Plugins aus.');
}

if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler auf bzw. es konnte kein Ergebnis ermittelt werden.'); 
}

close (sock);

set_kb_item(name:"GSHB-10/M4_093/result", value:result);
set_kb_item(name:"GSHB-10/M4_093/desc", value:desc);
set_kb_item(name:"GSHB-10/M4_093/name", value:name);

silence = get_kb_item("GSHB-10/silence");

if (silence){
exit(0);
} else {
  report = 'Ergebnisse zum IT-Grundschutz, 10. Erg�nzungslieferung:\n\n';
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
