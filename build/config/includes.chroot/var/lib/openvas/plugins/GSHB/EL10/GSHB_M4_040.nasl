###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_040.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 10. EL, Maﬂnahme 4.040
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
tag_summary = "IT-Grundschutz M4.040: Verhinderung der unautorisierten Nutzung des Rechnermikrofons.

  Diese Pr¸fung bezieht sich auf die 10. Erg‰nzungslieferung (10. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
  Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

  http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04040.html";


if(description)
{
  script_id(94040);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Tue May 11 16:10:57 2010 +0200");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.040: Verhinderung der unautorisierten Nutzung des Rechnermikrofons");
  if (! OPENVAS_VERSION)
  {
    desc = "
    Leider setzen Sie einen zu alten OpenVAS Scan-Server ein.
    Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!";
    script_description(desc);
    script_summary("IT-Grundschutz M4.040: Verhinderung der unautorisierten Nutzung des Rechnermikrofons.");
    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
    script_family("IT-Grundschutz-10");
    exit(0);
  }
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("IT-Grundschutz M4.040: Verhinderung der unautorisierten Nutzung des Rechnermikrofons.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-10");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-10");
  script_dependencies("GSHB/GSHB_WMI_OSInfo.nasl", "GSHB/GSHB_SSH_audio.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.040: Verhinderung der unautorisierten Nutzung des Rechnermikrofons\n';

if (! OPENVAS_VERSION)
{
        set_kb_item(name:"GSHB-10/M4_040/result", value:"nicht zutreffend");
        set_kb_item(name:"GSHB-10/M4_040/desc", value:"Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!");
        set_kb_item(name:"GSHB-10/M4_040/name", value:name);
    log_message(port:0, proto: "IT-Grundschutz", data:string("Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!"));  
    exit(0);
}


gshbm =  "IT-Grundschutz M4.040: ";
OSNAME = get_kb_item("WMI/WMI_OSNAME");
package = get_kb_item("GSHB/AUDIO/package");
devaudio = get_kb_item("GSHB/AUDIO/devaudio");
log = get_kb_item("GSHB/AUDIO/log");

syslog = get_kb_item("GSHB/syslog");
rsyslog = get_kb_item("GSHB/rsyslog");
log_rsyslog = get_kb_item("GSHB/rsyslog/log");

if(OSNAME >!< "none"){
  result = string("unvollst‰ndig");
  desc = string('Es ist unter Windows nicht mˆglich, den Status des Micros ¸ber Registry/WMI auszulesen.'); 
}
else if(devaudio != "windows") {
    if("error" >< devaudio){
    result = string("Fehler");
    if (!log_rsyslog) desc = string("Beim Testen des Systems trat ein Fehler auf.");
    if (log_rsyslog) desc = string("Beim Testen des Systems trat ein Fehler auf: " + log);
  }else if (devaudio == "no audio"){
    result = string("erf¸llt");
    desc = string('In Ihrem System konnte keine Audio-Komponenten ermittelt werden um ein Microfone anzuschlieﬂen.'); 
  }else if (devaudio =~ ".......---.*root.audio.*" && package == "none"){
    result = string("erf¸llt");
    desc = string('Der zugriff auf /dev/audio ist auf root beschr‰nkt und es wurde keine\nder folgenden Audio-Server Pakete gefunden: esound, paudio, pulseaudio, artsd, phonon');
  }else if (devaudio !~ ".......---.*root.audio.*" || package != "none") {
    result = string("nicht erf¸llt");  
    if (devaudio !~ ".......---.*root.audio.*")desc = string('Sie sollten den Zugriff auf /dev/audio auf root beschr‰nken. ');
    if (package != "none")desc += string('Folgende Audioserver Pakete wurden auf dem System gefunden:\n' + package);
  }
}
else{
  result = string("Fehler");
  desc = string('Beim Testen des Systems konnte dies nicht korrekt erkannt werden.\nSollte es sich um ein Windows-System handeln, ist es nicht mˆglich den Status des Micros ¸ber Registry/WMI auszulesen.'); 
}

if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler auf bzw. es konnte kein Ergebnis ermittelt werden.'); 
}

set_kb_item(name:"GSHB-10/M4_040/result", value:result);
set_kb_item(name:"GSHB-10/M4_040/desc", value:desc);
set_kb_item(name:"GSHB-10/M4_040/name", value:name);

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
