##############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_333.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 11. EL, Ma�nahme 4.333
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
tag_summary = "IT-Grundschutz M4.333: Sichere Konfiguration von Winbind unter Samba

  Diese Pr�fung bezieht sich auf die 11. Erg�nzungslieferung (11. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Ma�nahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Erg�nzungslieferung bezieht. Titel und Inhalt k�nnen sich bei einer
  Aktualisierung �ndern, allerdings nicht die Kernthematik.

  http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04333.html";


if(description)
{
  script_id(894333);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Tue Jun 01 10:37:06 2010 +0200");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.333: Sichere Konfiguration von Winbind unter Samba");
  if (! OPENVAS_VERSION)
  {
    desc = "
    Leider setzen Sie einen zu alten OpenVAS Scan-Server ein.
    Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!";
    script_description(desc);
    script_summary("IT-Grundschutz M4.333: Sichere Konfiguration von Winbind unter Samba");
    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
    script_family("IT-Grundschutz-11");
    exit(0);
  }
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("IT-Grundschutz M4.333: Sichere Konfiguration von Winbind unter Samba");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-11");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-11");
  script_dependencies("find_service.nasl", "ssh_authorization.nasl", "gather-package-list.nasl", "GSHB/GSHB_SSH_fstab.nasl","GSHB/GSHB_SSH_Samba.nasl","netbios_name_get.nasl", "GSHB/GSHB_SSH_nsswitch.nasl" );
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.333: Sichere Konfiguration von Winbind unter Samba\n';

if (! OPENVAS_VERSION)
{
        set_kb_item(name:"GSHB-11/M4_333/result", value:"nicht zutreffend");
        set_kb_item(name:"GSHB-11/M4_333/desc", value:"Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!");
        set_kb_item(name:"GSHB-11/M4_333/name", value:name);
    log_message(port:0, proto: "IT-Grundschutz", data:string("Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!"));  
    exit(0);
}

samba = get_kb_item("SMB/samba");
global = get_kb_item("GSHB/SAMBA/global");
reiserfs = get_kb_item("GSHB/FSTAB/reiserfs");
global = tolower(global);
log = get_kb_item("GSHB/SAMBA/log");
SSHUNAME = get_kb_item("ssh/login/uname");
passwd = get_kb_item("GSHB/nsswitch/passwd");
group = get_kb_item("GSHB/nsswitch/group");

if (SAMBA || (SSHUNAME && ("command not found" >!< SSHUNAME && "CYGWIN" >!< SSHUNAME))){
  rpms = get_kb_item("ssh/login/packages");
  if (rpms){
    pkg1 = "winbind";
    pat1 = string("ii  (", pkg1, ") +([0-9]:)?([^ ]+)");
    desc1 = eregmatch(pattern:pat1, string:rpms);
  }else{
    rpms = get_kb_item("ssh/login/rpms");
    tmp = split(rpms, keep:0);
    if (max_index(tmp) <= 1)rpms = ereg_replace(string:rpms, pattern:";", replace:'\n');
    pkg1 = "winbind";
    pat1 = string("(", pkg1, ")~([0-9a-zA-Z/.-_/+]+)~([0-9a-zA-Z/.-_]+)");
    desc1 = eregmatch(pattern:pat1, string:rpms);
  }
}
if (desc1) winbind = "yes";
else winbind = "no";



if(global != "none" && global != "novalentrys"){
  Lst = split(global,keep:0);
  for(i=0; i<max_index(Lst); i++){
    if ("security" >< Lst[i]) security = Lst[i];
    if ("idmap backend" >< Lst[i]) idmapbackend = Lst[i];
    if ("template homedir" >< Lst[i]) templatehd = Lst[i];
    if ("idmap domains" >< Lst[i]) idmapdomains = Lst[i];
    if ("idmap config" >< Lst[i]) idmapconfig += Lst[i] + '\n';
  }
}

if (!security) security = "false";
if (!idmapbackend) idmapbackend = "false";
if (!templatehd) templatehd = "false";
if (!idmapdomains) idmapdomains = "false";
if (!idmapconfig) idmapconfig = "false";
if (!passwd) passwd = "false";
if (!group) group = "false";

if(!samba){
    result = string("nicht zutreffend");
    desc = string('Auf dem System l�uft kein Samba-Dateiserver.');
}else if(winbind == "no"){
    result = string("nicht zutreffend");
    desc = string('Auf dem System ist winbind nicht installiert.');
}else if("winbind" >!< passwd){
    result = string("nicht zutreffend");
    desc = string('Auf dem System ist winbind �ber /etc/nsswitch.conf\nnicht eingebunden.');
}else if(global == "error"){
  result = string("Fehler");
  if (!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
  if (log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log); 
}else if("domain" >!< security && "ads" >!< security){
  result = string("nicht zutreffend");
  desc = string('Der Samba Server auf dem System l�uft nicht im\n-domain- oder -ads- Security-Modus.');
}else{
  if ((idmapbackend == "false" || idmapbackend == "tdb") && reiserfs != "noreiserfs"){
    result = string("nicht erf�llt");  
    desc = string('Auf dem System l�uft folgende Partition mit ReiserFS:\n' + reiserfs +'\nIhr -idmap backend- ist auf tdb eingestellt.\nS�mtliche Samba-Datenbanken im TDB-Format sollten auf\neiner Partition gespeichert werden, die nicht ReiserFS\nals Dateisystem verwendet.');
  }else if(templatehd == "false" || '/%d/%u' >!< templatehd){
    result = string("nicht erf�llt");
    desc = string('Die Dom�ne des Benutzers sollte in den Pfad seines\nHeimatverzeichnisses aufgenommen werden. Diese\nMa�name verhindert Namenskollisionen bei\nVertrauensstellungen.');
  }else{
    if (idmapbackend == "false" || idmapbackend == "tdb"){
      result = string("erf�llt");
      desc = string('Existieren Vertrauensstellungen zwischen Dom�nen im\nInformationsverbund, so muss eines der folgenden ID-\nMapping-Backends verwendet werden:\n- Backend rid mit idmap domains Konfiguration.\n- Backend ldap mit idmap domains Konfiguration.\n- Backend ad.\n- Backend nss.');
    }else if ("rid" >< idmapbackend || "ldap" >< idmapbackend){
      result = string("erf�llt");    
      if ("rid" >< idmapbackend && idmapdomains != "false" && idmapconfig != "false") desc = string('Sie benutzen das ID-Mapping-Backend -rid- mit\nfolgender Konfiguration:\n' + idmapdomains + idmapconfig);
      else if ("ldap" >< idmapbackend && idmapdomains != "false" && idmapconfig != "false") desc = string('Sie benutzen das ID-Mapping-Backend -ldap- mit\nfolgender Konfiguration:\n' + idmapdomains + idmapconfig);
      else if ("rid" >< idmapbackend && (idmapdomains == "false" || idmapconfig == "false")) desc = string('Sie benutzen das ID-Mapping-Backend -rid-.\nExistieren Vertrauensstellungen zwischen Dom�nen im\nInformationsverbund,so muss -idmap domains-\nkonfiguriert werden.');
      else if ("ldap" >< idmapbackend && (idmapdomains == "false" || idmapconfig == "false")) desc = string('Sie benutzen das ID-Mapping-Backend -ldap-.\nExistieren Vertrauensstellungen zwischen Dom�nen im\nInformationsverbund, so muss -idmap domains-\nkonfiguriert werden.');
      
    }else{
      result = string("erf�llt");    
      if ("nss" >< idmapbackend) desc = string('Sie benutzen das ID-Mapping-Backend -nss-');
      else if ("ad" >< idmapbackend) desc = string('Sie benutzen das ID-Mapping-Backend -ad-');
    }
  }
}

if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler\nauf bzw. es konnte kein Ergebnis ermittelt werden.'); 
}

set_kb_item(name:"GSHB-11/M4_333/result", value:result);
set_kb_item(name:"GSHB-11/M4_333/desc", value:desc);
set_kb_item(name:"GSHB-11/M4_333/name", value:name);

silence = get_kb_item("GSHB-11/silence");

if (silence){
exit(0);
} else {
  report = 'Ergebnisse zum IT-Grundschutz, 11. Erg�nzungslieferung:\n\n';
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
