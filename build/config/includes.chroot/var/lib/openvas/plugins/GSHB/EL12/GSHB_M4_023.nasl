###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_023.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 12. EL, Ma�nahme 4.023
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
tag_summary = "IT-Grundschutz M4.023: Sicherer Aufruf ausf�hrbarer Dateien.

Diese Pr�fung bezieht sich auf die 12. Erg�nzungslieferung (12. EL) des IT-
Grundschutz. Die detaillierte Beschreibung zu dieser Ma�nahme findet sich unter
nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
die aktuellste Erg�nzungslieferung bezieht. Titel und Inhalt k�nnen sich bei einer
Aktualisierung �ndern, allerdings nicht die Kernthematik.

http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04023.html";


if(description)
{
  script_id(94038);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2011-11-07 13:38:53 +0100 (Mon, 07 Nov 2011)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.023: Sicherer Aufruf ausf�hrbarer Dateien");
  script_add_preference(name:"Alle Dateien Auflisten", type:"checkbox", value:"no");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("IT-Grundschutz M4.023: Sicherer Aufruf ausf�hrbarer Dateien.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-12");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-12");
  script_dependencies("GSHB/GSHB_WMI_PathVariables.nasl", "GSHB/GSHB_WMI_OSInfo.nasl", "GSHB/GSHB_SSH_executable_path.nasl", "find_service.nasl", "ssh_authorization.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


name = 'IT-Grundschutz M4.023: Sicherer Aufruf ausf�hrbarer Dateien\n';

gshbm =  "IT-Grundschutz M4.023: ";

include("ssh_func.inc");

OSVER = get_kb_item("WMI/WMI_OSVER");
OSWINDIR = get_kb_item("WMI/WMI_OSWINDIR");
WINPATH = get_kb_item("WMI/WinPathVar");
WINPATHFOR = split(WINPATH, sep:";", keep:0);
WMIOSLOG = get_kb_item("WMI/WMI_OS/log");

executable = get_kb_item("GSHB/executable");
writeexecutable = get_kb_item("GSHB/write-executable");
path = get_kb_item("GSHB/path");
exlog = get_kb_item("GSHB/executable/log");

log = get_kb_item("WMI/WinPathVar/log");

verbose = script_get_preference("Alle Dateien Auflisten");

sock = ssh_login_or_reuse_connection();

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
    if (log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
  }else
  {
    for(p=0; p<max_index(WINPATHFOR); p++)
    {
      if(OSWINDIR >!< WINPATHFOR[p])PATH = "FALSE";
      else PATH = "TRUE";
      PATHCHECK = PATHCHECK + PATH;
    }
    WINPATH = ereg_replace(string:WINPATH, pattern: ';', replace:';\\n');
    if ("FALSE" >< PATHCHECK){
      result = string("nicht erf�llt");
      desc = string('Das System enth�lt folgende PATH-Variable:\n' + WINPATH + '\nBitte pr�fen Sie auch die Benutzervariablen, da nur\ndie Systemvariable f�r PATH gepr�ft werden konnte.');
    }else{
      result = string("erf�llt");
      desc = string('Das System enth�lt folgende PATH-Variable:\n' + WINPATH + '\nBitte pr�fen Sie auch die Benutzervariablen, da nur\ndie Systemvariable f�r PATH gepr�ft werden konnte.');
    }





  }
}else if(executable !~ "(I|i)nvalid switch" && writeexecutable !~ "(I|i)nvalid switch" ){

  path = split(path, sep:'"', keep:0);
  path = split(path[1], sep:":", keep:0);
  for (i=0; i<max_index(path); i++){
    if (path[i] >!< "./") continue;
    Lst1 += path[i] + ":";
  }
  if (!Lst1) path = "none";
  else path = Lst1;
  
  if(executable >< "error"){
    result = string("Fehler");
    if (!exlog)desc = string('Beim Testen des Systems trat ein unbekannter\nFehler auf.');
    if (exlog && log)desc = string('Beim Testen des Systems traten folgende Fehler auf:\n'+ log + '\n' + exlog);
    else if (exlog && !log)desc = string('Beim Testen des Systems trat ein Fehler auf:\n' + exlog);
  }else if(path >!< "none" || executable >!< "none" || writeexecutable >!< "none" ||  tripwire == "no"){
    result = string("nicht erf�llt");
    if (path >!< "none") desc = string('Folgende PATH-Variable sollte entfernt werden:\n' + path + '\n\n');
    if (writeexecutable >!< "none") desc += string('\nFolgende Dateien sind f�r Benutzer ausf�hrbar und\nbeschreibbar:\n' + writeexecutable + '\n\n');
    if (verbose == "yes"){
      if (executable >!< "none") desc += string('Folgende, au�erhalb von /usr/local/bin/:/usr/bin/:\n/bin/:/usr/games/:/sbin/:/usr/sbin/:/usr/local/sbin/:\n/var/lib/:/lib/:/usr/lib/:/etc/:/opt/slad/, liegende\nDateien sind f�r Benutzer ausf�hrbar und sollten\nentfernt bzw. die Rechte ge�ndert werden:\n' + executable + '\n\n');
    }else{
      if (executable >!< "none") desc += string('Au�erhalb von /usr/local/bin/:/usr/bin/:/bin/:\n/usr/games/:/sbin/:/usr/sbin/:/usr/local/sbin/:\n/var/lib/:/lib/:/usr/lib/:/etc/:/opt/slad/, wurden\nDateien gefunden, die f�r Benutzer ausf�hrbar sind.\nSie sollten entfernt, bzw. es sollten die Rechte\nge�ndert werden.\nF�r eine vollst�ndige Liste w�hlen\nSie bei den Voreinstellungen dieses Tests: Alle\nDateien Auflisten\n');
    }
    if (sladlst == "noslad")desc += string('Auf dem System ist SLAD nicht installiert.\n');
    if (tripwire == "no")desc += string('\nAuf dem System ist das SLAD-Plugin -Tripwire- nicht\ninstalliert. Entsprechend kann die Integrit�t der\nausf�hrbaren Dateien nicht regelm��ig verifiziert\nwerden.\n');
  }else{
    result = string("erf�llt");
    desc = string("Das System gen�gt den Anforderungen\nder Ma�nahme 4.023.\n");
    desc += string('Auf dem System ist Slad mit den Slad Plugin -Tripwire-\ninstalliert. F�hren Sie bitte eine OpenVAS-Pr�fung\nIhres Netzwerkes mit dem genannten SLAD Plugin aus.\n');    
  }

}else {
  if (path =~ "/cygdrive/./(W|w)indows"){
    result = string("Fehler");
    if (!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
    if (log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
  }else{
    result = string("Fehler");
    if (!exlog)desc = string('Beim Testen des Systems trat ein unbekannter\nFehler auf.');
    if (exlog)desc = string('Beim Testen des Systems trat ein Fehler auf:\n' + exlog);
  }

}

if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler\nauf bzw. es konnte kein Ergebnis ermittelt werden.'); 
}



set_kb_item(name:"GSHB-12/M4_023/result", value:result);
set_kb_item(name:"GSHB-12/M4_023/desc", value:desc);
set_kb_item(name:"GSHB-12/M4_023/name", value:name);

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
