###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_288.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 10. EL, Maﬂnahme 4.288
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
tag_summary = "IT-Grundschutz M4.288: Sichere Administration von VoIP-Endger‰ten.

  Diese Pr¸fung bezieht sich auf die 10. Erg‰nzungslieferung (10. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
  Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

  http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04288.html";


if(description)
{
  script_id(94288);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Fri Jun 04 14:04:07 2010 +0200");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.288: Sichere Administration von VoIP-Endger‰ten");
  script_add_preference(name:"Pruefung ausfuehren. Sie sollte allerdings nur gegen 1 System mit installiertem SLAD-Snort Plugin laufen.", type:"checkbox", value:"no");
  if (! OPENVAS_VERSION)
  {
    desc = "
    Leider setzen Sie einen zu alten OpenVAS Scan-Server ein.
    Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!";
    script_description(desc);
    script_summary("IT-Grundschutz M4.288: Sichere Administration von VoIP-Endger‰ten.");
    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
    script_family("IT-Grundschutz-10");
    exit(0);
  }
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("IT-Grundschutz M4.288: Sichere Administration von VoIP-Endger‰ten.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-10");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-10");
  script_dependencies("find_service.nasl", "ssh_authorization.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


name = 'IT-Grundschutz M4.288: Sichere Administration von VoIP-Endger‰ten\n';

if (! OPENVAS_VERSION)
{
        set_kb_item(name:"GSHB-10/M4_288/result", value:"nicht zutreffend");
        set_kb_item(name:"GSHB-10/M4_288/desc", value:"Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!");
        set_kb_item(name:"GSHB-10/M4_288/name", value:name);
    log_message(port:0, proto: "IT-Grundschutz", data:string("Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!"));  
    exit(0);
}


gshbm =  "IT-Grundschutz M4.288: ";

starttest = script_get_preference("Pruefung ausfuehren. Sie sollte allerdings nur gegen 1 System mit installiertem SLAD-Snort Plugin laufen.");

function run_slad_snort (sock, slad_exe) {
  global_var snortresult;
  slad_cmd = slad_exe + " -r snort:snort:snort";
  results = ssh_cmd (socket: sock, cmd: slad_cmd, timeout: 30);
  if (results)  snortresult = results; 
}
  
if (starttest == "yes"){

include ("ssh_func.inc");
include ("slad.inc");

  sock = ssh_login_or_reuse_connection();
  if(!sock) {
    val = get_ssh_error();
  }

  if (!val && sock){
     run_slad_snort (sock: sock, slad_exe: "/opt/slad/bin/sladd");
    if ("403 plugin already running" >< snortresult || "200 queued" >< snortresult)
    {
      slad_exe = '/opt/slad/bin/sladd';
      slad_cmd = slad_exe + ' -s jobs';
      report = ssh_cmd (socket:sock, cmd:slad_cmd, timeout:60);
      bhead = report;
      while (bhead) {
        eol = strstr (bhead, string ("\n"));
        line = substr (bhead, 0, strlen (bhead) - strlen (eol) -1);
        bhead = substr (bhead, strlen (line) + 1);
        parts = split (line, sep: ':', keep: FALSE);
        job = parts[1] + ":" + parts[2] + ":" + parts[3];
        desc = get_slad_description (entry: job);
        if (parts[0] == "R" && parts[1] == "snort" && parts[2] == "snort" && parts[3] == "snort") {
          running += string (desc + "\n");
        } else if (parts[0] == "T" && parts[1] == "snort" && parts[2] == "snort" && parts[3] == "snort") {
          results += string (desc + "\n");
          slad_cmd = slad_exe + ' -s ' + job;
          results += ssh_cmd (socket:sock, cmd:slad_cmd, timeout:60);
          results += string ("\n");
        }
      }
      if (results){
        results = ereg_replace(string:results, pattern: '<!--.*-->', replace:'');
      }
      if (!running && !results) results="none";
      else if (!running){
        if ("TFTP" >< results){
          result = string("nicht erf¸llt");
          desc = string('Bei Auslesen der SNORT-Resultate wurde festgestellt, dass Sie unsicheren TFTP Verkehr in Ihrem Netz haben.\n\n' + results); 
        }else{
          result = string("erf¸llt");
          desc = string('Bei Auslesen der SNORT-Resultate konnt kein unsicheren TFTP Verkehr in Ihrem Netz erkannt werden.\n\n' + results); 
        }

      }
      else if (running){
        result = string("unvollst‰ndig");
        desc = string("Zur Zeit l‰uft der SLAD-Test noch. Bitte wiederholen Sie den test sp‰ter nochmal."); 
      }
    }else {
      if (!snortresult){
        result = string("Fehler");
        desc = string("Es konnte kein Ergebnis ermittelt werden."); 
      }else if ( "/opt/slad/bin/sladd: No such file or directory" >< snortresult || "/opt/slad/bin/sladd: Datei oder Verzeichnis nicht gefunden" >< snortresult ){
        result = string("Fehler");
        desc = string("Auf dem Zielsystem ist SLAD / WinSLAD nicht installiert"); 
      }else{
        result = string("unvollst‰ndig");
        desc = string('Folgendes unvollst‰ndige Ergebnis wurde ermittelt:' + snortresult); 
      }      
    }
    close (sock);
  }else {
    result = string("Fehler");
    if (val)desc = string('Beim Testen des Systems trat ein Fehler auf:\n' + val); 
    else if (!soc) desc = string('Beim Testen des Systems trat ein Fehler auf:\nEs konnte keine SSH Verbindung aufgebaut werden.');
    else desc = string('Beim Testen des Systems trat ein unbekannter Fehler auf.');
  }
}else{
  result = string("nicht zutreffend");
  desc = string('Der Test wurde in den Voreinstellungen nicht aktiviert. Dieser Test sollte nur gegen ein einziges System laufen.\nAuf diesem muﬂ SLAD oder WinSLAD und das Snort-Plugin installiert sein und Snort sollte von dort aus das Netz ¸berwachen.'); 

}

if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler auf bzw. es konnte kein Ergebnis ermittelt werden.'); 
}

set_kb_item(name:"GSHB-10/M4_288/result", value:result);
set_kb_item(name:"GSHB-10/M4_288/desc", value:desc);
set_kb_item(name:"GSHB-10/M4_288/name", value:name);

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
