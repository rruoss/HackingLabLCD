###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_023.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 10. EL, Maßnahme 4.023
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
tag_summary = "IT-Grundschutz M4.023: Sicherer Aufruf ausführbarer Dateien.

  Diese Prüfung bezieht sich auf die 10. Ergänzungslieferung (10. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Maßnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Ergänzungslieferung bezieht. Titel und Inhalt können sich bei einer
  Aktualisierung ändern, allerdings nicht die Kernthematik.

  http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04023.html";


if(description)
{
  script_id(94023);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Thu Jan 14 14:29:35 2010 +0100");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.023: Sicherer Aufruf ausführbarer Dateien");
  script_add_preference(name:"Alle Dateien Auflisten", type:"checkbox", value:"no");
  if (! OPENVAS_VERSION)
  {
    desc = "
    Leider setzen Sie einen zu alten OpenVAS Scan-Server ein.
    Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!";
    script_description(desc);
    script_summary("IT-Grundschutz M4.023: Sicherer Aufruf ausführbarer Dateien.");
    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
    script_family("IT-Grundschutz-10");
    exit(0);
  }
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("IT-Grundschutz M4.023: Sicherer Aufruf ausführbarer Dateien.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-10");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-10");
  script_dependencies("GSHB/GSHB_WMI_PathVariables.nasl", "GSHB/GSHB_WMI_OSInfo.nasl", "GSHB/GSHB_SSH_executable_path.nasl", "find_service.nasl", "ssh_authorization.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


name = 'IT-Grundschutz M4.023: Sicherer Aufruf ausführbarer Dateien\n';

if (! OPENVAS_VERSION)
{
        set_kb_item(name:"GSHB-10/M4_023/result", value:"nicht zutreffend");
        set_kb_item(name:"GSHB-10/M4_023/desc", value:"Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!");
        set_kb_item(name:"GSHB-10/M4_023/name", value:name);
    log_message(port:0, proto: "IT-Grundschutz", data:string("Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!"));  
    exit(0);
}


gshbm =  "IT-Grundschutz M4.023: ";


include("ssh_func.inc");

OSVER = get_kb_item("WMI/WMI_OSVER");
OSWINDIR = get_kb_item("WMI/WMI_OSWINDIR");
WINPATH = get_kb_item("WMI/WinPathVar");
WINPATHFOR = split(WINPATH, sep:";", keep:0);

executable = get_kb_item("GSHB/executable");
writeexecutable = get_kb_item("GSHB/write-executable");
path = get_kb_item("GSHB/path");
exlog = get_kb_item("GSHB/executable/log");

log = get_kb_item("WMI/WinPathVar/log");

verbose = script_get_preference("Alle Dateien Auflisten");

sladlst = ssh_cmd (socket: sock, cmd: "/opt/slad/bin/sladd -s plugins", timeout: 120);
if (sladlst =~ ".*Datei oder Verzeichnis nicht gefunden.*" ||  sladlst =~ ".*No such file or directory.*") sladlst = "noslad";
else if (!sladlst)  sladlst = "none";

if (sladlst != "noslad" && sladlst != "none"){
  Lst = split(sladlst, keep:0);
  for(i=0; i<max_index(Lst); i++){  
    if (Lst[i] =~ "p:tripwire.*") tripwire = "yes";
  }
}

if (!tripwire) tripwire = "no";

if(OSVER >!< "none"){
  if(!OSVER){
    result = string("Fehler");
    if (!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
    if (log) desc = string("Beim Testen des Systems trat ein Fehler auf: " + log);
  }else
  {
    for(p=0; p<max_index(WINPATHFOR); p++)
    {
      if(OSWINDIR >!< WINPATHFOR[p])PATH = "FALSE";
      else PATH = "TRUE";
      PATHCHECK = PATHCHECK + PATH;
    }
    if ("FALSE" >< PATHCHECK)
    {
    result = string("nicht erfüllt");
    desc = string('Das System enthält folgende PATH-Variable:\n' + WINPATH + '\nBitte prüfen Sie auch die Benutzervariablen, da nur die Systemvariable für PATH geprüft werden konnte.');
    }
    else
    {
    result = string("erfüllt");
    desc = string('Das System enthält folgende PATH-Variable:\n' + WINPATH + '\nBitte prüfen Sie auch die Benutzervariablen, da nur die Systemvariable für PATH geprüft werden konnte.');
    }
  }
}else if(executable !~ "(I|i)nvalid switch" && writeexecutable !~ "(I|i)nvalid switch" ){

  path = split(path, sep:'"', keep:0);
  path = split(path[1], sep:":", keep:0);
  for (i=0; i<max_index(path); i++){
    if (path[i] >!< "./") continue;
    Lst += path[i] + ":";
  }
  if (!Lst) path = "none";
  else path = Lst;
  
  if(executable >< "error"){
    result = string("Fehler");
    if (!exlog)desc = string('Beim Testen des Systems trat ein unbekannter Fehler auf.');
    if (exlog && log)desc = string('Beim Testen des Systems traten folgende Fehler auf:\n'+ log + '\n' + exlog);
    else if (exlog && !log)desc = string('Beim Testen des Systems trat ein Fehler auf:\n' + exlog);
  }else if(path >!< "none" || executable >!< "none" || writeexecutable >!< "none" ||  tripwire == "no"){
    result = string("nicht erfüllt");
    if (path >!< "none") desc = string('Folgende PATH-Variable sollte entfernt werden: ' + path + '\n');
    if (writeexecutable >!< "none") desc += string('Folgende Dateien sind für Benutzer ausführbar und beschreibbar:\n' + writeexecutable + '\n');
    if (verbose == "yes"){
      if (executable >!< "none") desc += string('Folgende, außerhalb von\n/usr/local/bin/:/usr/bin/:/bin/:/usr/games/:/sbin/:/usr/sbin/:/usr/local/sbin/:/var/lib/:/lib/:/usr/lib/:/etc/:/opt/slad/,\nliegende Dateien sind für Benutzer ausführbar und sollten entfernt bzw. die Rechte geändert werden:\n' + executable + '\n');
    }else{
      if (executable >!< "none") desc += string('Außerhalb von\n/usr/local/bin/:/usr/bin/:/bin/:/usr/games/:/sbin/:/usr/sbin/:/usr/local/sbin/:/var/lib/:/lib/:/usr/lib/:/etc/:/opt/slad/,\nwurden Dateien gefunden, die für Benutzer ausführbar sind. Sie sollten entfernt, bzw. es sollten die Rechte geändert werden.\nFür eine vollständige Liste wählen Sie bei den Voreinstellungen dieses Tests: Alle Dateien Auflisten');
    }
    if (sladlst == "noslad")desc += string('\nAuf dem System ist SLAD nicht installiert.');
    if (tripwire == "no")desc += string('\nAuf dem System ist das SLAD-Plugin -Tripwire- nicht installiert.\nEntsprechend kann die Integrität der ausführbaren Dateien nicht regelmäßig verifiziert werden.');
  }else{
    result = string("erfüllt");
    desc = string("Das System genügt den Anforderungen der Maßnahme 4.023.");
    desc += string('\nAuf dem System ist Slad mit den Slad Plugin -Tripwire- installiert.\nFühren Sie bitte eine OpenVAS-Prüfung Ihres Netzwerkes mit dem genannten SLAD Plugin aus.');    
  }

}else {
  if (path =~ "/cygdrive/./(W|w)indows"){
    result = string("Fehler");
    if (!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
    if (log) desc = string("Beim Testen des Systems trat ein Fehler auf: " + log);
  }else{
    result = string("Fehler");
    if (!exlog)desc = string('Beim Testen des Systems trat ein unbekannter Fehler auf.');
    if (exlog)desc = string('Beim Testen des Systems trat ein Fehler auf:\n' + exlog);
  }

}

if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler auf bzw. es konnte kein Ergebnis ermittelt werden.'); 
}


set_kb_item(name:"GSHB-10/M4_023/result", value:result);
set_kb_item(name:"GSHB-10/M4_023/desc", value:desc);
set_kb_item(name:"GSHB-10/M4_023/name", value:name);

silence = get_kb_item("GSHB-10/silence");

if (silence){
exit(0);
} else {
  report = 'Ergebnisse zum IT-Grundschutz, 10. Ergänzungslieferung:\n\n';
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
