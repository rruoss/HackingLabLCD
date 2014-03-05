###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M5_064.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 10. EL, Maﬂnahme 5.064
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
tag_summary = "IT-Grundschutz M5.064: Secure Shell.

  Diese Pr¸fung bezieht sich auf die 10. Erg‰nzungslieferung (10. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
  Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

  http://www.bsi.bund.de/grundschutz/kataloge/m/m05/m05064.html";

if(description)
{
  script_id(95064);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Mon Feb 08 15:35:47 2010 +0100");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M5.064: Secure Shell");
  
  if (! OPENVAS_VERSION)
  {
    desc = "Leider setzen Sie einen zu alte OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!";
    script_description(desc);
    script_summary("IT-Grundschutz M5.064: Secure Shell.");
    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
    script_family("IT-Grundschutz-10");
    exit(0);
  }
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("IT-Grundschutz M5.064: Secure Shell.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-10");
  script_mandatory_keys("Compliance/Launch/GSHB-10");
#  script_require_ports("Services/ssh", 22);
  script_dependencies("find_service.nasl", "ssh_detect.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M5.064: Secure Shell\n';



if (! OPENVAS_VERSION)
  {
        set_kb_item(name:"GSHB-10/M5_064/result", value:"nicht zutreffend");
        set_kb_item(name:"GSHB-10/M5_064/desc", value:"Leider setzen Sie einen zu alte OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!");
        set_kb_item(name:"GSHB-10/M5_064/name", value:name);
    log_message(port:0, proto: "IT-Grundschutz", data:string("Leider setzen Sie einen zu alte OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!"));  
    exit(0);
}

include("ssh_func.inc");
include("version_func.inc");

gshbm =  "IT-Grundschutz M5.064: ";

port = get_preference("auth_port_ssh");
if(!port) port = get_kb_item("Services/ssh");
if(!port) port = 22;

sock = ssh_login_or_reuse_connection();
if(!sock) sshsock = "no";
else if(sock) sshsock = "yes";
close(sock);

sshbanner = get_kb_item("SSH/banner/" + port);
if (sshbanner){
  sshbanner = tolower(sshbanner);
  version = eregmatch(pattern:"ssh-.*openssh[_-]{1}([0-9.]+[p0-9]*)", string: sshbanner);
}
else sshbanner = "none";



if(sshbanner == "none" && sshsock = "no"){
  result = string("nicht zutreffend");
  desc = string("Es wurde kein SSH-Server gefunden");
}else if(sshbanner == "none" && sshsock = "yes"){
  result = string("unvollst‰ndig");
  desc = string("Es wurde ein SSH-Server gefunden. Allerdings konnte weder der\nTyp noch die Version erkannt werden.");
}else if("openssh" >< sshbanner){

  if(version_is_less(version: version[1], test_version: "5.2")){
    result = string("nicht erf¸llt");
    desc = string('Es wurde auf Port ' + port + ', folgender SSH-Server gefunden: ' + sshbanner + '\nVersionen vor OpenSSH 5.2 sind verwundbar.');
  }else{
    result = string("erf¸llt");
    desc = string('Es wurde auf Port ' + port + ', folgender SSH-Server gefunden: ' + sshbanner + '\nVersionen vor OpenSSH 5.2 sind verwundbar.');
  } 
}else{
    result = string("unvollst‰ndig");
    desc = string('Es wurde auf Port ' + port + ', folgender SSH-Server gefunden: ' + sshbanner + '\nIm Moment wird nur auf OpenSSH Server getestet.\nVersionen vor OpenSSH 5.2 sind verwundbar.');
} 


set_kb_item(name:"GSHB-10/M5_064/result", value:result);
set_kb_item(name:"GSHB-10/M5_064/desc", value:desc);
set_kb_item(name:"GSHB-10/M5_064/name", value:name);

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

