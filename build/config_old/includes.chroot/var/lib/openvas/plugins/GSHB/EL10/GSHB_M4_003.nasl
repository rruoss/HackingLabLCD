###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_003.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 10. EL, Ma�nahme 4.003
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
tag_summary = "IT-Grundschutz M4.003: Regelm��iger Einsatz eines Anti-Viren-Programms.

  Diese Pr�fung bezieht sich auf die 10. Erg�nzungslieferung (10. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Ma�nahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Erg�nzungslieferung bezieht. Titel und Inhalt k�nnen sich bei einer
  Aktualisierung �ndern, allerdings nicht die Kernthematik.

  http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04003.html";

if(description)
{
  script_id(94003);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Thu Jan 14 14:29:35 2010 +0100");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.003: Regelm��iger Einsatz eines Anti-Viren-Programms");
  
  if (! OPENVAS_VERSION)
  {
    desc = "Leider setzen Sie einen zu alte OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!";
    script_description(desc);
    script_summary("IT-Grundschutz M4.003: Regelm��iger Einsatz eines Anti-Viren-Programms.");
    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
    script_family("IT-Grundschutz-10");
    exit(0);
  }
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("IT-Grundschutz M4.003: Regelm��iger Einsatz eines Anti-Viren-Programms.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-10");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-11");
  script_dependencies("GSHB/GSHB_WMI_Antivir.nasl", "gather-package-list.nasl");
#  script_require_keys("WMI/Antivir");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.003: Regelm��iger Einsatz eines Anti-Viren-Programms\n';



if (! OPENVAS_VERSION)
  {
        set_kb_item(name:"GSHB-10/M4_003/result", value:"nicht zutreffend");
        set_kb_item(name:"GSHB-10/M4_003/desc", value:"Leider setzen Sie einen zu alte OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!");
        set_kb_item(name:"GSHB-10/M4_003/name", value:name);
    log_message(port:0, proto: "IT-Grundschutz", data:string("Leider setzen Sie einen zu alte OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!"));  
    exit(0);
}

gshbm =  "IT-Grundschutz M4.003: ";

SAMBA = get_kb_item("SMB/samba");
SSHUNAME = get_kb_item("ssh/login/uname");

if (SAMBA || (SSHUNAME && ("command not found" >!< SSHUNAME && "CYGWIN" >!< SSHUNAME))){
  rpms = get_kb_item("ssh/login/packages"); 
  if (rpms){
    pkg1 = "clamav";
    pkg2 = "clamav-freshclam";

    pat1 = string("ii  (", pkg1, ") +([0-9]:)?([^ ]+)");
    pat2 = string("ii  (", pkg2, ") +([0-9]:)?([^ ]+)");
    desc1 = eregmatch(pattern:pat1, string:rpms);
    desc2 = eregmatch(pattern:pat2, string:rpms);
    
    name1 = desc1[1];
    version1 = desc1[3];
    name2 = desc2[1];
    version2 = desc2[3];
        
  }else if(rpms = get_kb_item("ssh/login/rpms")){
    tmp = split(rpms, keep:0);
    if (max_index(tmp) <= 1){
      tmp = split(rpms,sep:";", keep:0);
      rpms = "";
      for (i=0; i<max_index(tmp); i++){
      rpms += tmp[i] + '\n';
      }
    }
    pkg1 = "clamav";
    pkg2 = "clamav-freshclam";
    pkg3 = "clamav-update";
   
    pat1 = string("(", pkg1, ")~([0-9/.]+)~([0-9a-zA-Z/.-_]+)");
    pat2 = string("(", pkg2, ")~([0-9/.]+)~([0-9a-zA-Z/.-_]+)");
    pat3 = string("(", pkg3, ")~([0-9/.]+)~([0-9a-zA-Z/.-_]+)");
    desc1 = eregmatch(pattern:pat1, string:rpms);
    desc2 = eregmatch(pattern:pat2, string:rpms);
    desc3 = eregmatch(pattern:pat3, string:rpms);
    if (desc1){
      name1 = desc1[1];
      version1 = desc1[2];
    }
    if (desc2){
      name2 = desc2[1];
      version2 = desc2[2];
    }else if (desc3){
      name2 = desc3[1];
      version2 = desc3[2];
    }
  }else{
     rpms = get_kb_item("ssh/login/solpackages");
     pkg1 = "clamav";
     pat1 = string("([a-zA-Z0-9]+)[ ]{1,}(.*", pkg1, ".*)[ ]{1,}([a-zA-Z0-9/\._ \(\),-:\+\{\}\&]+)");
     
    desc1 = eregmatch(pattern:pat1, string:rpms);     
    if (desc1){
      name1 = desc1[3];
    }

  }
  if(!SSHUNAME){
    result = string("Fehler");
    desc = string("Ein Login �ber SSH war nicht erfolgreich.");
  }else if(!rpms){
    result = string("Fehler");
    desc = string("Vom System konnte keine Paketliste mit installierter\nSoftware geladen werden.");
  }else if(SSHUNAME =~ "SunOS.*"){
    if(!desc1){
      result = string("nicht erf�llt");
      desc = string("Die Antivirensoftware ClamAV konnte nicht auf dem\nSystem gefunden werden.");
    }else if(desc1){
      result = string("erf�llt");
      desc = string('Die Antivirensoftware ClamAV konnte auf dem System\ngefunden werden. Folgende Version ist installiert:\n' + name1);
    }
  }else if(!desc1 && (!desc2 || !desc3)){
    result = string("nicht erf�llt");
    desc = string("Die Antivirensoftware ClamAV konnte nicht auf dem\nSystem gefunden werden.");
  }else if(desc1 && (!desc2 && !desc3)){
    result = string("nicht erf�llt");
    desc = string("Die Antivirensoftware ClamAV konnte auf dem System\ngefunden werden, allerdings wurde Freshclam/ClamAV-\nupdate nicht installiert.");
  }else if(desc1 && (desc2 || desc3)){
    result = string("erf�llt");
    desc = string('Die Antivirensoftware ClamAV konnte auf dem System\ngefunden werden. Folgende Version ist installiert:\n' + name1 + "  " + version1 + '\n' + name2 + "  " + version2);
  }else{
      result = string("Fehler");
      desc = string("Beim Testen des Systems trat ein unbekannter Fehler auf.");
  }
}

else if (!SAMBA && (!SSHUNAME || "command not found" >< SSHUNAME || "CYGWIN" >< SSHUNAME)){
  log = get_kb_item("WMI/Antivir/log");
  Antivir = get_kb_item("WMI/Antivir");
  if(!Antivir) Antivir = "None";
  AntivirName = get_kb_item("WMI/Antivir/Name");
  AntivirUptoDate = get_kb_item("WMI/Antivir/UptoDate");
  if (AntivirUptoDate >!< "None") AntivirUptoDate = split(AntivirUptoDate, sep:"|", keep:0);
  AntivirEnable = get_kb_item("WMI/Antivir/Enable");
  if (AntivirEnable >!< "None") AntivirEnable = split(AntivirEnable, sep:"|", keep:0);
  AntivirState = get_kb_item("WMI/Antivir/State");
  if (AntivirState >!< "None") AntivirState = split(AntivirState, sep:"|", keep:0);

  if(Antivir >< "error"){
    result = string("Fehler");
    if(!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
    if(log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
  }else if(Antivir >< "Server"){
    result = string("nicht zutreffend");
    desc = string("Das System ist ein Windows Server. Solche Systeme \nk�nnen leider nicht getestet werden");
  }else if(Antivir >< "None"){
    result = string("nicht erf�llt");
    desc = string("Auf dem System wurde kein Antivierenprogramm gefunden");
  }else if(Antivir >< "Windows XP <= SP1"){
    result = string("nicht zutreffend");
    desc = string("Das System ist ein Windows XP System kleiner oder\ngleich Service Pack 1 und kann nicht getestet werden");
  }else if(AntivirName >!< "None" && AntivirState >< "None"){
      if ("True" >< AntivirEnable[2] && "True" >< AntivirUptoDate[2]){
        result = string("erf�llt");
        desc = string("Das System hat einen Virenscanner installiert,\nwelcher l�uft und aktuell ist.");
      }else if ("True" >< AntivirEnable[2] && "False" >< AntivirUptoDate[2]){
        result = string("nicht erf�llt");
        desc = string("Das System hat einen Virenscanner istalliert,\nwelcher l�uft aber veraltet ist.");
      }else if ("False" >< AntivirEnable[2] && "True" >< AntivirUptoDate[2]){
        result = string("nicht erf�llt");
        desc = string("Das System hat einen Virenscanner installiert,\nwelcher aus aber aktuell ist.");
      }else if ("False" >< AntivirEnable[2] && "False" >< AntivirUptoDate[2]){
        result = string("nicht erf�llt");
        desc = string("Das System hat einen Virenscanner installiert,\nwelcher aus und veraltet ist.");
      }
  }else if(AntivirName >!< "None" && AntivirState >!< "None"){
      if ("266240" >< AntivirState[2]){
        result = string("erf�llt");
        desc = string("Das System hat einen Virenscanner installiert,\nwelcher l�uft und aktuell ist.");
      }else if ("266256" >< AntivirState[2]){
        result = string("nicht erf�llt");
        desc = string("Das System hat einen Virenscanner installiert,\nwelcher l�uft aber veraltet ist.");
      }else if ("262144"  >< AntivirState[2] || "270336" >< AntivirState[2]){
        result = string("nicht erf�llt");
        desc = string("Das System hat einen Virenscanner installiert,\nwelcher aus aber aktuell ist.");
      }else if ("262160"  >< AntivirState[2] || "270352" >< AntivirState[2]){
        result = string("nicht erf�llt");
        desc = string("Das System hat einen Virenscanner installiert,\nwelcher aus und veraltet ist.");
      }
  }else{
      result = string("Fehler");
      desc = string("Beim Testen des Systems trat ein unbekannter\nFehler auf.");
  }
}  

else{
      result = string("Fehler");
      desc = string("Beim Testen des Systems trat ein unbekannter\nFehler auf.");
}
  
set_kb_item(name:"GSHB-10/M4_003/result", value:result);
set_kb_item(name:"GSHB-10/M4_003/desc", value:desc);
set_kb_item(name:"GSHB-10/M4_003/name", value:name);

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

