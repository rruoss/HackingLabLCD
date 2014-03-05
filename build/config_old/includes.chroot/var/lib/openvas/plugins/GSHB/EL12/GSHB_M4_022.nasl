###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_022.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 12. EL, Ma�nahme 4.022
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
tag_summary = "IT-Grundschutz M4.022: Verhinderung des Vertraulichkeitsverlusts schutzbed�rftiger Daten im Unix-System.

Diese Pr�fung bezieht sich auf die 12. Erg�nzungslieferung (12. EL) des IT-
Grundschutz. Die detaillierte Beschreibung zu dieser Ma�nahme findet sich unter
nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
die aktuellste Erg�nzungslieferung bezieht. Titel und Inhalt k�nnen sich bei einer
Aktualisierung �ndern, allerdings nicht die Kernthematik.

http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04022.html";

if(description)
{
  script_id(94035);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2011-11-07 13:38:53 +0100 (Mon, 07 Nov 2011)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.022: Verhinderung des Vertraulichkeitsverlusts schutzbed�rftiger Daten im Unix-System");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("IT-Grundschutz M4.022: Verhinderung des Vertraulichkeitsverlusts schutzbed�rftiger Daten im Unix-System.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-12");
  script_mandatory_keys("Compliance/Launch/GSHB-12");
  script_dependencies("GSHB/GSHB_SSH_prev_sensitive_data_loss.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.022: Verhinderung des Vertraulichkeitsverlusts schutzbed�rftiger Daten im Unix-System\n';

gshbm =  "IT-Grundschutz M4.022: ";


ps = get_kb_item("GSHB/ps");
finger = get_kb_item("GSHB/finger");
who = get_kb_item("GSHB/who");
last = get_kb_item("GSHB/last");
tmpfiles = get_kb_item("GSHB/tmpfiles");
log = get_kb_item("GSHB/ps/log");

   
OSNAME = get_kb_item("WMI/WMI_OSNAME");

if(OSNAME >!< "none"){
  result = string("nicht zutreffend");
  desc = string('Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nFolgendes System wurde erkannt:\n' + OSNAME);
}else if(ps == "windows") {
    result = string("nicht zutreffend");
    desc = string('Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nDas System scheint ein Windows-System zu sein.');
}else if(ps >< "error"){
  result = string("Fehler");
  if (!log)desc = string('Beim Testen des Systems trat ein unbekannter\nFehler auf.');
  if (log)desc = string('Beim Testen des Systems trat ein Fehler auf:\n' + log);
}
if (result != "nicht zutreffend" && result != "Fehler"){
  if(ps == "none" || finger == "none" || who == "none" || last == "none" || tmpfiles == "none"){
    if(ps == "none"){
      result_ps = string("Fehler");
      if (result_ps != "Fehler")desc += string('Fehler: Beim Testen des Systems wurde festgestellt,\ndass die Datei /bin/ps nicht gefunden werden konnte.\n');
    }
    if(finger == "none"){
      result_finger = string("Fehler");
      if (result_finger != "Fehler")desc += string('Fehler: Beim Testen des Systems wurde festgestellt,\ndass die Datei /usr/bin/finger nicht gefunden\nwerden konnte.\n');
    }
    if(who == "none"){
      result_finger = string("Fehler");
      if (result_finger != "Fehler")desc += string('Fehler: Beim Testen des Systems wurde festgestellt,\ndass die Datei /usr/bin/who nicht gefunden\nwerden konnte.\n');
    }
    if(last == "none"){
      result_last = string("Fehler");
      if (result_last != "Fehler")desc += string('Fehler: Beim Testen des Systems wurde festgestellt,\ndass die Datei /usr/bin/last nicht gefunden\nwerden konnte.\n');
    }
    if(tmpfiles == "none"){
      result_tmpfiles = string("Fehler");
      if (result_tmpfiles != "Fehler")desc += string('Fehler: Beim Testen des Systems wurde festgestellt,\ndass die Dateien /var/log/?tmp* nicht gefunden\nwerden konnten.\n');
    }
  }
##############
  if(ps != "none"){
    if (ps =~ "-(r|-)(w|-)(x|-)(r|-)(w|-)(x|-)---.*"){
      result_ps = string("ok");
      desc += string('Beim Testen des Systems wurden f�r die Datei /bin/ps\nfolgende korrekte Sicherheiteinstellungen\nfestgestellt: ' + ps + '\n\n'); 
    }
    else{
      result_ps = string("fail");
      if (ps =~ "-(rwx)(r|-)(w|-)(x|-).*")secval = "-rwxr-x---";
      else if (ps =~ "-(r-x)(r|-)(w|-)(x|-).*")secval = "-r-xr-x---";
      desc += string('Fehler: Beim Testen des Systems wurden f�r die Datei\n/bin/ps folgende fehlerhafte Sicherheitseinstellungen\nfestgestellt: ' + ps + '\nBitte �ndern Sie diese auf ' + secval + ' \n\n' ); 
    }
  }
##############
  if(finger != "none"){
    if (finger =~ "-(r|-)(w|-)(x|-)(r|-)(w|-)(x|-)---.*"){
      result_finger = string("ok");
      desc += string('Beim Testen des Systems wurden f�r die Datei\n/usr/bin/finger folgende korrekte Sicherheitsein-\nstellungen festgestellt: ' + finger + '\n\n'); 
    }
    else{
      result_finger = string("fail");
      if (finger =~ "-(rwx)(r|-)(w|-)(x|-).*")secval = "-rwxr-x---";
      else if (finger =~ "-(r-x)(r|-)(w|-)(x|-).*")secval = "-r-xr-x---";
      desc += string('Fehler: Beim Testen des Systems wurden f�r die Datei\n/usr/bin/finger folgende fehlerhafte Sicherheitsein-\nstellungen festgestellt: ' + finger + '\nBitte �ndern Sie diese auf ' + secval + ' \n\n' ); 
    }
  }
##############
  if(who != "none"){
    if (who =~ "-(r|-)(w|-)(x|-)(r|-)(w|-)(x|-)---.*"){
      result_who = string("ok");
      desc += string('Beim Testen des Systems wurden f�r die Datei\n/usr/bin/who folgende korrekte Sicherheitsein-\nstellungen festgestellt: ' + who + '\n\n'); 
    }
    else{
      result_who = string("fail");
      if (who =~ "-(rwx)(r|-)(w|-)(x|-).*")secval = "-rwxr-x---";
      else if (who =~ "-(r-x)(r|-)(w|-)(x|-).*")secval = "-r-xr-x---";
      desc += string('Fehler: Beim Testen des Systems wurden f�r die Datei\n/usr/bin/who folgende fehlerhafte Sicherheitsein-\nstellungen festgestellt: ' + who + '\nBitte �ndern Sie diese auf ' + secval + ' \n\n' ); 
    }
  }
##############
  if(last != "none"){
    if (last =~ "-(r|-)(w|-)(x|-)(r|-)(w|-)(x|-)---.*"){
      result_last = string("ok");
      desc += string('Beim Testen des Systems wurden f�r die Datei\n/usr/bin/last folgende korrekte Sicherheitsein-\nstellungen festgestellt: ' + last + '\n\n'); 
    }
    else{
      result_last = string("fail");
      if (last =~ "-(rwx)(r|-)(w|-)(x|-).*")secval = "-rwxr-x---";
      else if (last =~ "-(r-x)(r|-)(w|-)(x|-).*")secval = "-r-xr-x---";
      desc += string('Fehler: Beim Testen des Systems wurden f�r die Datei\n/usr/bin/last folgende fehlerhafte Sicherheitsein-\nstellungen festgestellt: ' + last + '\nBitte �ndern Sie diese auf ' + secval + ' \n\n' ); 
    }
  }
##############
  if(tmpfiles != "none"){
    Lst = split(tmpfiles, keep:0);
    for (i=0; i<max_index(Lst); i++){
        if (Lst[i] !~ "-rw-(r|-)(w|-)----.*"){
          faillist += Lst[i] + '\n';
        }
    } 
    if(!faillist){
      result_tmpfiles = string("ok");
      desc += string('Beim Testen des Systems wurden f�r die Dateien\n/var/log/?tmp* folgende korrekte Sicherheitsein-\nstellungen festgestellt: ' + tmpfiles + '\n\n'); 
    }
    else{
      result_tmpfiles = string("fail");
      desc += string('Fehler: Beim Testen des Systems wurden f�r die Dateien\n/var/log/?tmp* folgende fehlerhafte Sicherheitsein-\nstellungen festgestellt: ' + faillist + '\nBitte �ndern Sie diese auf -rw-rw----.\n\n' );
    }   
  }
##############
  if(!result && (result_ps == "fail" ||  result_finger == "fail" || result_who == "fail" || result_last == "fail" || result_tmpfiles == "fail")) result = string("nicht erf�llt");
  else if(!result && (result_ps == "Fehler"|| result_finger == "Fehler" || result_who == "Fehler" || result_last == "Fehler" || result_tmpfiles == "Fehler")) result = string("Fehler");
  else if (!result && result_ps == "ok" && result_finger == "ok" && result_who == "ok" && result_last == "ok" && result_tmpfiles == "ok")result = string("erf�llt");
}
if (!result){
      result = string("Fehler");
      desc = string('Beim Testen des Systems trat ein unbekannter Fehler\nauf bzw. es konnte kein Ergebnis ermittelt werden.'); 
}

set_kb_item(name:"GSHB-12/M4_022/result", value:result);
set_kb_item(name:"GSHB-12/M4_022/desc", value:desc);
set_kb_item(name:"GSHB-12/M4_022/name", value:name);

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
