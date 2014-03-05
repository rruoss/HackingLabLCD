###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M5_034.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 11. EL, Maßnahme 5.034
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
tag_summary = "IT-Grundschutz M5.034: Einsatz von Einmalpasswörtern

  Diese Prüfung bezieht sich auf die 11. Ergänzungslieferung (11. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Maßnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Ergänzungslieferung bezieht. Titel und Inhalt können sich bei einer
  Aktualisierung ändern, allerdings nicht die Kernthematik.

  http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m05034.html";


if(description)
{
  script_id(895034);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Thu Apr 29 16:41:47 2010 +0200");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M5.034: Einsatz von Einmalpasswörtern");
  if (! OPENVAS_VERSION)
  {
    desc = "
    Leider setzen Sie einen zu alten OpenVAS Scan-Server ein.
    Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!";
    script_description(desc);
    script_summary("IT-Grundschutz M5.034: Einsatz von Einmalpasswörtern");
    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
    script_family("IT-Grundschutz-11");
    exit(0);
  }
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("IT-Grundschutz M5.034: Einsatz von Einmalpasswörtern");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-11");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-11");
  script_dependencies("GSHB/GSHB_WMI_OSInfo.nasl", "GSHB/GSHB_SSH_Opie.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M5.034: Einsatz von Einmalpasswörtern\n';

if (! OPENVAS_VERSION)
{
        set_kb_item(name:"GSHB-11/M5_034/result", value:"nicht zutreffend");
        set_kb_item(name:"GSHB-11/M5_034/desc", value:"Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers.");
        set_kb_item(name:"GSHB-11/M5_034/name", value:name);
    log_message(port:0, proto: "IT-Grundschutz", data:string("Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers."));  
    exit(0);
}

gshbm =  "IT-Grundschutz M5.034: ";

OSNAME = get_kb_item("WMI/WMI_OSNAME");
OPISERVICES = get_kb_item("GSHB/OPIE/SERVICES");
OPIPAM = get_kb_item("GSHB/OPIE/PAM");
OPISSH = get_kb_item("GSHB/OPIE/SSH");
OPISERVER = get_kb_item("GSHB/OPIE/SERVER");
OPICLIENT = get_kb_item("GSHB/OPIE/CLIENT");
log = get_kb_item("GSHB/OPIE/log");

if(OSNAME >!< "none"){
  result = string("nicht zutreffend");
  desc = string('Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nFolgendes System wurde erkannt:\n' + OSNAME);
}else if(OPISERVER >< "windows"){
  result = string("nicht zutreffend");
  desc = string('Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nDas System ist ein Windows-System.');
}else if(OPISERVER >< "error"){
  result = string("Fehler");
  if (!log)desc = string('Beim Testen des Systems trat ein unbekannter Fehler auf.');
  if (log)desc = string('Beim Testen des Systems trat ein Fehler auf:\n' + log);
}else if (OPISERVER == "yes" && (OPIPAM == "norights" || OPISERVICES == "norights")){
  result = string("Fehler");
  if (OPIPAM == "norights") desc = string('Der Testbenutzer hat kein Recht auf die Datei\n/etc/pam.d/opie zu lesen.');
#  if (OPISSH == "norights") desc += string('\nDer Testbenutzer hat kein Recht auf die Datei\n/etc/ssh/sshd_config zu lesen.');
  if (OPISERVICES == "norights") desc += string('\nDer Testbenutzer hat kein Recht die Dateien unter\n/etc/pam.d/ zu lesen');
}else if (OPISERVER == "yes" && (OPIPAM == "nocat" || OPISSH == "nogrep" || OPISERVICES == "nogrep")){
  result = string("Fehler");
  if (OPIPAM == "nocat") desc = string('Der Befehl -cat- wurde nicht gefunden.');
  if (OPISSH == "nogrep" || OPISERVICES == "nogrep") desc += string('\nDer Befehl -grep- wurde nicht gefunden.');
}

else if(OPISERVER == "no"){
  result = string("unvollständig");
  desc = string('Wir testen im Moment nur auf Opie, welches auf diesem System\nnicht installiert ist. Bitte überprüfen Sie manuell, ob eine\nandere One-Time-Password Software installiert ist. Ansonsten\nist ein Einsatz von Einmalpasswörtern nicht möglich.');
}else {

  if ( "auth sufficient pam_opie.so" >< OPIPAM && "auth required pam_deny.so" >< OPIPAM ){
    result = string("erfüllt");
    if (OPISSH == "norights") desc = string('\nDer Testbenutzer hat kein Recht auf die Datei\n/etc/ssh/sshd_config zu lesen. In dieser Datei sollte der\nEintrag -ChallengeResponseAuthentication yes- stehen, damit\nauch SSH mit Einmalpasswörtern arbeiten kann.');
    else if ("ChallengeResponseAuthentication yes" >!< OPISSH) desc = string('In der Datei /etc/ssh/sshd_config, sollte der Eintrag\n-ChallengeResponseAuthentication yes- stehen, damit auch SSH\nmit Einmalpasswörtern arbeiten kann.');
    if (OPISERVICES == "empty") desc += string('\nUm OPIE mit den verschiedenen Authentisierungsdiensten\nverwenden zu können, muss die Datei /etc/pam.d/opie in die\nPAM-Konfigurationen der jeweiligen Dienste eingebunden werden.\nDazu muss in der Datei /etc/pam.d/<Dienstname> der Eintrag\n-@include common-auth- durch -@include opie- ersetzt werden.');
    else desc += string('\nFolgende Dienste arbeiten schon mit Opie zusammen:\n' + OPISERVICES + '\nUm weitere hinzuzufügen, muss in der Datei\n/etc/pam.d/<Dienstname> der Eintrag -@include common-auth-\ndurch -@include opie- ersetzt werden.');
  }else{
    result = string("nicht erfüllt");
    desc = string("Die Datei /etc/pam.d/opie muss angelegt werden und es sollten\nmindestens die Einträge -auth sufficient pam_opie.so- und\n-auth required pam_deny.so- in ihr stehen.");
  }
}

if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler auf\nbzw. es konnte kein Ergebnis ermittelt werden.'); 
}

set_kb_item(name:"GSHB-11/M5_034/result", value:result);
set_kb_item(name:"GSHB-11/M5_034/desc", value:desc);
set_kb_item(name:"GSHB-11/M5_034/name", value:name);

silence = get_kb_item("GSHB-11/silence");

if (silence){
exit(0);
} else {
  report = 'Ergebnisse zum IT-Grundschutz, 11. Ergänzungslieferung:\n\n';
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
