###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_147.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 12. EL, Maﬂnahme 4.147
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
tag_summary = "IT-Grundschutz M4.147: Sichere Nutzung von EFS unter Windows (Win).

Diese Pr¸fung bezieht sich auf die 12. Erg‰nzungslieferung (12. EL) des IT-
Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04147.html";


if(description)
{
  script_id(94064);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2011-11-07 13:38:53 +0100 (Mon, 07 Nov 2011)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.147: Sichere Nutzung von EFS unter Windows (Win)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("IT-Grundschutz M4.147: Sichere Nutzung von EFS unter Windows (Win).");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-12");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-12");
  script_dependencies("GSHB/GSHB_WMI_EFS.nasl, GSHB/GSHB_WMI_OSInfo.nasl", "GSHB/GSHB_SMB_SDDL.nasl", "GSHB/GSHB_WMI_Hibernate.nasl");  
  script_require_keys("WMI/WMI_EncrDir", "WMI/WMI_EncrFile", "WMI/WMI_EFSAlgorithmID");
  
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.147: Sichere Nutzung von EFS unter Windows (Win)\n';

OSVER = get_kb_item("WMI/WMI_OSVER");
OSNAME = get_kb_item("WMI/WMI_OSNAME");
OSSP = get_kb_item("WMI/WMI_OSSP");
OSTYPE = get_kb_item("WMI/WMI_OSTYPE");
WMIOSLOG = get_kb_item("WMI/WMI_OS/log");
EncrFile = get_kb_item("WMI/WMI_EncrFile");
EncrFile = ereg_replace(pattern:'Name\n', string:EncrFile, replace:''); 
EncrDir = get_kb_item("WMI/WMI_EncrDir");
EncrDir = ereg_replace(pattern:'Name\n', string:EncrDir, replace:''); 
EFSAlgorithmID = get_kb_item("WMI/WMI_EFSAlgorithmID");
AUTOEXECSDDL = get_kb_item("GSHB/AUTOEXECSDDL");
log = get_kb_item("WMI/WMI_EFS/log");
stat =  get_kb_item("GSHB/WINSDDL/stat");

if (OSVER == '5.0')
{
#Jeder
if(AUTOEXECSDDL =~ "\(A;.*;0x001f01ff;;;WD\)") USER += "Jeder - Vollzugriff, ";
if(AUTOEXECSDDL =~ "\(A;.*;0x001301bf;;;WD\)") USER += "Jeder - ƒndern, ";
if(AUTOEXECSDDL =~ "\(A;.*;0x001201bf;;;WD\)") USER += "Jeder - Schreiben, ";
#Authentifizierte User
if(AUTOEXECSDDL =~ "\(A;.*;0x001f01ff;;;AU\)") USER += "Authentifizierte User - Vollzugriff, ";
if(AUTOEXECSDDL =~ "\(A;.*;0x001301bf;;;AU\)") USER += "Authentifizierte User - ‰ndernden Zugriff, ";
if(AUTOEXECSDDL =~ "\(A;.*;0x001201bf;;;AU\)") USER += "Authentifizierte User - schreibenden Zugriff, ";
#Benutzer
if(AUTOEXECSDDL =~ "\(A;.*;0x001f01ff;;;S-1-5-32-545\)") USER += "Benutzer - Vollzugriff, ";
if(AUTOEXECSDDL =~ "\(A;.*;0x001301bf;;;S-1-5-32-545\)") USER += "Benutzer - ‰ndernden Zugriff, ";
if(AUTOEXECSDDL =~ "\(A;.*;0x001201bf;;;S-1-5-32-545\)") USER += "Benutzer - schreibenden Zugriff, ";
#Hauptbenutzer
if(AUTOEXECSDDL =~ "\(A;.*;0x001f01ff;;;S-1-5-32-547\)") USER += "Hauptbenutzer - Vollzugriff, ";
if(AUTOEXECSDDL =~ "\(A;.*;0x001301bf;;;S-1-5-32-547\)") USER += "Hauptbenutzer - ‰ndernden Zugriff, ";
if(AUTOEXECSDDL =~ "\(A;.*;0x001201bf;;;S-1-5-32-547\)") USER += "Hauptbenutzer - schreibenden Zugriff, ";
#G‰ste
if(AUTOEXECSDDL =~ "\(A;.*;0x001f01ff;;;BG\)") USER += "G‰ste - Vollzugriff, ";
if(AUTOEXECSDDL =~ "\(A;.*;0x001301bf;;;BG\)") USER += "G‰ste - ‰ndernden Zugriff, ";
if(AUTOEXECSDDL =~ "\(A;.*;0x001201bf;;;BG\)") USER += "G‰ste - schreibenden Zugriff, ";
}

if (EFSAlgorithmID == "none")
{
    if (OSVER == '5.0'){
      EFSAlgorithmID = "DESX";
    }else if (OSVER == '5.1' &&  OSSP == "Without SP"){
      EFSAlgorithmID = "DESX";
    }else if (OSVER == '5.1' &&  OSSP >= 1){
      EFSAlgorithmID = "AES-256";
    }
}
else if (EFSAlgorithmID == "6603"){
  EFSAlgorithmID = "3DES";
}
else if (EFSAlgorithmID == "6604"){
  EFSAlgorithmID = "DESX";
}
else if (EFSAlgorithmID == "6610"){
  EFSAlgorithmID = "AES-256";
}

gshbm =  "IT-Grundschutz M4.147: ";

if (WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System."){
  result = string("nicht zutreffend");
  desc = string("Auf dem System l‰uft Samba, es ist kein\nMicrosoft Windows System.");
  }else if(!stat){
    result = string("Fehler");
    desc = string("Beim Testen des Systems trat ein Fehler auf.\nEs konnte keine File and Folder ACL abgerufen werden.");
  }else if(EncrFile >< "error" && EncrDir >< "error" && EFSAlgorithmID >< "error"){
    result = string("Fehler");
    if (!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
    if (log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
} else if(OSVER == '5.0' || OSVER == '5.1' || OSNAME >< 'Microsoft(R) Windows(R) XP Professional x64 Edition' || (OSVER > '5.2' && OSTYPE == 1)){

    if (EncrFile  == "none" && EncrDir == "none"){
      result = string("nicht zutreffend");
      desc = string("Auf dem Systems gibt es keine EFS-verschl¸sselten\nDaten.");
    }
    
    else{
    
      if (OSVER > '5.0'){
        result = string("erf¸llt");
        desc = string('Auf dem Systems gibt es folgende EFS-verschl¸sselten\nDaten:\n' + EncrDir +  EncrFile + '\nDabei wird folgendes Verschl¸sselungsverfahren\neingesetzt: ' + EFSAlgorithmID + '\nBitte beachten Sie auch, dass Sie ein dediziertes\nKonto f¸r den Wiederherstellungsagenten erzeugen und\ndessen privaten Schl¸ssel sichern und aus dem System\nentfernen sollten. Auﬂerdem sollten Sie die syskey-\nVerschl¸sselung mit Passwort verwendet, wenn EFS mit\nlokalen Konten eingesetzt wird');
      }else{
      
        if(USER){
          result = string("nicht erf¸llt");
          desc = string('Auf dem System existieren EFS-verschl¸sselte Dateien.\nDabei haben folgende Benutzer\n' + USER + '\nzugriff auf die Datei autoexec.bat.\nDie Windows Boot-Datei autoexec.bat muss vor\nVerschl¸sselung gesch¸tzt werden, indem f¸r Benutzer\nder Schreibzugriff unterbunden wird, da sonst eine\nDenial-of-Service-Attacke mˆglich ist.');
        }else{
        result = string("erf¸llt");
        desc = string('Auf dem Systems gibt es folgende EFS-verschl¸sselten\nDaten:\n' + EncrDir +  EncrFile + '\nDabei wird folgendes Verschl¸sselungsverfahren\neingesetzt: ' + EFSAlgorithmID + '\nBitte beachten Sie auch, dass Sie ein dediziertes\nKonto f¸r den Wiederherstellungsagenten erzeugen und\\ndessen privaten Schl¸ssel sichern und aus dem System\nentfernen sollten. Auﬂerdem sollten Sie die syskey-\nVerschl¸sselung mit Passwort verwendet, wenn EFS mit\nlokalen Konten eingesetzt wird');
        }
      
      }
    }
   
} else{
  result = string("nicht zutreffend");
  desc = string("Das System ist kein Windows Client");
}

set_kb_item(name:"GSHB-12/M4_147/result", value:result);
set_kb_item(name:"GSHB-12/M4_147/desc", value:desc);
set_kb_item(name:"GSHB-12/M4_147/name", value:name);

silence = get_kb_item("GSHB-12/silence");

if (silence){
exit(0);
} else {
  report = 'Ergebnisse zum IT-Grundschutz, 12. Erg‰nzungslieferung:\n\n';
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
