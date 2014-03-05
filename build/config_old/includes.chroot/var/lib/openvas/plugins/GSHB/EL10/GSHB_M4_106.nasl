###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_106.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 10. EL, Maﬂnahme 4.106
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
tag_summary = "IT-Grundschutz M4.106: Aktivieren der Systemprotokollierung.

  Diese Pr¸fung bezieht sich auf die 10. Erg‰nzungslieferung (10. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
  Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

  http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04106.html";


if(description)
{
  script_id(94106);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Mon Apr 26 16:31:33 2010 +0200");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.106: Aktivieren der Systemprotokollierung");
  if (! OPENVAS_VERSION)
  {
    desc = "
    Leider setzen Sie einen zu alten OpenVAS Scan-Server ein.
    Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!";
    script_description(desc);
    script_summary("IT-Grundschutz M4.106: Aktivieren der Systemprotokollierung.");
    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
    script_family("IT-Grundschutz-10");
    exit(0);
  }
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("IT-Grundschutz M4.106: Aktivieren der Systemprotokollierung.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-10");
  script_mandatory_keys("Compliance/Launch/GSHB-10");
  script_dependencies("GSHB/GSHB_WMI_OSInfo.nasl", "GSHB/GSHB_SSH_syslog.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


name = 'IT-Grundschutz M4.106: Aktivieren der Systemprotokollierung\n';

if (! OPENVAS_VERSION)
{
        set_kb_item(name:"GSHB-10/M4_106/result", value:"nicht zutreffend");
        set_kb_item(name:"GSHB-10/M4_106/desc", value:"Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!");
        set_kb_item(name:"GSHB-10/M4_106/name", value:name);
    log_message(port:0, proto: "IT-Grundschutz", data:string("Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!"));  
    exit(0);
}


gshbm =  "IT-Grundschutz M4.106: ";

OSNAME = get_kb_item("WMI/WMI_OSNAME");
var_log = get_kb_item("GSHB/var_log");
var_adm = get_kb_item("GSHB/var_adm");
syslog = get_kb_item("GSHB/syslog");
rsyslog = get_kb_item("GSHB/rsyslog");
syslogr = get_kb_item("GSHB/syslogr");
rsyslogr = get_kb_item("GSHB/rsyslogr");
log = get_kb_item("GSHB/rsyslog/log");
    
    
if(OSNAME >!< "none"){
  result = string("nicht zutreffend");
  desc = string('Dieser Test bezieht sich auf UNIX/LINUX Systeme. Das System ist ein ' + OSNAME + ' System.');
}else if(rsyslog == "windows") {
    result = string("nicht zutreffend");
    desc = string('Dieser Test bezieht sich auf UNIX/LINUX Systeme. Das System scheint ein Windows-System zu sein.');
}else if(rsyslog >< "error"){
  result = string("Fehler");
  if (!log)desc = string('Beim Testen des Systems trat ein unbekannter Fehler auf, siehe Log Message!');
  if (log)desc = string('Beim Testen des Systems trat ein Fehler auf:\n' + log);
}else if((var_log =~ "d......r...*" || var_adm =~ "d......r...*") || (syslogr =~ "........w..*" || rsyslogr =~ "........w..*")){
  result = string("nicht erf¸llt");
  if (var_log =~ "d......r...*" && var_adm =~ "d......r...*") desc = string('F¸r die Verzeichnisse /var/log und /var/adm sind ˆffentliche Leserechte eingestellt, bitte ‰ndern Sie das:' + '\n/var/log: ' + var_log + '\n/var/adm: ' + var_adm);
  else if (var_log =~ "d......r...*") desc = string('F¸r das Verzeichnis /var/log sind ˆffentliche Leserechte eingestellt, bitte ‰ndern Sie das:' + '\n/var/log: ' + var_log);
  else if (var_adm =~ "d......r...*") desc = string('F¸r das Verzeichnis /var/adm sind ˆffentliche Leserechte eingestellt, bitte ‰ndern Sie das:' + '\n/var/adm: '  + var_adm);
  if (syslogr =~ "........w..*" || rsyslogr =~ "........w..*")desc += string('\nF¸r die Dateien /etc/syslog.conf und /etc/rsyslog.conf sind ˆffentliche Schreibrechte eingestellt, bitte ‰ndern Sie das: ' + '\n/etc/syslog.conf: ' + syslogr + '\n/etc/rsyslog.conf: ' + rsyslogr);
  else if (syslogr =~ "........w..*") desc += string('\nF¸r die Datei /etc/syslog.conf sind ˆffentliche Schreibrechte eingestellt, bitte ‰ndern Sie das: ' + '\n/etc/syslog.conf: ' + syslogr);
  else if (rsyslogr =~ "........w..*") desc += string('\nF¸r die Datei /etc/rsyslog.conf sind ˆffentliche Schreibrechte eingestellt, bitte ‰ndern Sie das: ' + '\n/etc/rsyslog.conf: ' + rsyslogr);
}else if((syslog == "none" && rsyslog == "norights") || (rsyslog == "none" && syslog == "norights") || (syslog == "norights" && rsyslog == "norights")){
  result = string("unvollst‰ndig");
  if(syslog == "norights" && rsyslog == "norights") desc = string('Sie haben kein Berechtigung die Dateien /etc/syslog.conf und /etc/rsyslog.conf zu lesen!');
  else if(rsyslog == "norights") desc = string('Sie haben kein Berechtigung die Datei /etc/rsyslog.conf zu lesen!');
  else if(syslog == "norights") desc = string('Sie haben kein Berechtigung die Datei /etc/syslog.conf zu lesen!');
}else if(syslog == "none" && rsyslog == "none"){
  result = string("Fehler");
  desc = string('Die Dateien /etc/syslog.conf und /etc/rsyslog.conf wurden nicht gefunden');
}else{
  result = string("unvollst‰ndig");
  desc = string('Die Berechtigungen f¸r /etc/var, /etc/log, /etc/syslog.conf bzw. /etc/rsyslog.conf sind korrekt gesetzt.\nBitte pr¸fen Sie ob unten angegebenen Parameter aus');
  if (syslog != "none") {
    Lst = split(syslog, keep:0);
    for (i=0; i<max_index(Lst); i++){
      if (Lst[i] == "") continue;
      parameter += Lst[i] + '\n';
    }
    desc += string(' der Datei /etc/syslog.conf, denen der Maﬂnahme 4.106 entsprechen.\n' + parameter);
  }
  else if (rsyslog != "none") {
    Lst = split(rsyslog, keep:0);
    for (i=0; i<max_index(Lst); i++){
      if (Lst[i] == "") continue;
      parameter += Lst[i] + '\n';
    }
    desc += string(' der Datei /etc/rsyslog.conf, denen der Maﬂnahme 4.106 entsprechen.\n' + parameter);
  }
}


if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler auf, bzw. es konnte kein Ergebnis ermittelt werden.'); 
}


set_kb_item(name:"GSHB-10/M4_106/result", value:result);
set_kb_item(name:"GSHB-10/M4_106/desc", value:desc);
set_kb_item(name:"GSHB-10/M4_106/name", value:name);

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
