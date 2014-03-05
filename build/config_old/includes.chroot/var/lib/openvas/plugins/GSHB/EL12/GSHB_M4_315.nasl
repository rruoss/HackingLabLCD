###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_315.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 12. EL, Maßnahme 4.315
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
tag_summary = "IT-Grundschutz M4.315: Aufrechterhaltung der Betriebssicherheit von Active Directory.

Diese Prüfung bezieht sich auf die 12. Ergänzungslieferung (12. EL) des IT-
Grundschutz. Die detaillierte Beschreibung zu dieser Maßnahme findet sich unter
nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
die aktuellste Ergänzungslieferung bezieht. Titel und Inhalt können sich bei einer
Aktualisierung ändern, allerdings nicht die Kernthematik.

http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04315.html";

if(description)
{
  script_id(94081);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2011-11-07 13:38:53 +0100 (Mon, 07 Nov 2011)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.315: Aufrechterhaltung der Betriebssicherheit von Active Directory");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("IT-Grundschutz M4.315: Aufrechterhaltung der Betriebssicherheit von Active Directory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-12");
  script_mandatory_keys("Compliance/Launch/GSHB-12");
  script_dependencies ("GSHB/GSHB_SLAD_MBSA_all.nasl","GSHB/GSHB_SLAD_fastjohn.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.315: Aufrechterhaltung der Betriebssicherheit von Active Directory\n';

gshbm =  "IT-Grundschutz M4.315: ";

OSDOMAINROLE = get_kb_item("WMI/WMI_WindowsDomainrole");

#MBSAALL = get_kb_item("GSHB/SLAD/MBSAALL");
MBSAALL = get_kb_item("GSHB/SLAD/MBSAALL");
FASTJOHN = get_kb_item("GSHB/SLAD/FASTJOHN");


if ("All rights reserved" >< MBSAALL){
  OSsepTest = split(MBSAALL, sep:'Issue:', keep:0);

  if ("Check failed" >< OSsepTest[2])  MBSAALLERR = "Issue:" + OSsepTest[2]; #Rubrik:  Windows-Sicherheitsupdates
  if ("Check failed" >< OSsepTest[5])  MBSAALLERR += "Issue:" + OSsepTest[5]; #Rubrik:  Kennwortablauf
  if ("Check failed" >< OSsepTest[6])  MBSAALLERR += "Issue:" + OSsepTest[6]; #Rubrik:  Gastkonto
  if ("Check failed" >< OSsepTest[8])  MBSAALLERR += "Issue:" + OSsepTest[8]; #Rubrik:  Einschränken anonymer Anmeldungen
  if ("Check failed" >< OSsepTest[9])  MBSAALLERR += "Issue:" + OSsepTest[9]; #Rubrik:  Administratoren
}
else if ("Alle Rechte vorbehalten" >< MBSAALL){
  OSsepTest = split(MBSAALL, sep:'Rubrik:', keep:0);
  if ("Fehler bei Überprüfung" >< OSsepTest[2])  MBSAALLERR = "Rubrik:" + OSsepTest[2]; #Rubrik:  Windows-Sicherheitsupdates
  if ("Fehler bei Überprüfung" >< OSsepTest[5])  MBSAALLERR += "Rubrik:" + OSsepTest[5]; #Rubrik:  Kennwortablauf
  if ("Fehler bei Überprüfung" >< OSsepTest[6])  MBSAALLERR += "Rubrik:" + OSsepTest[6]; #Rubrik:  Gastkonto
  if ("Fehler bei Überprüfung" >< OSsepTest[8])  MBSAALLERR += "Rubrik:" + OSsepTest[8]; #Rubrik:  Einschränken anonymer Anmeldungen
  if ("Fehler bei Überprüfung" >< OSsepTest[9])  MBSAALLERR += "Rubrik:" + OSsepTest[9]; #Rubrik:  Administratoren
}

#for(O=0; O<max_index(OSsepTest); O++){
#  security_hole(port:0, proto: "IT-Grundschutz-" + O, data:OSsepTest[O]);
#}


if(OSDOMAINROLE < 4 || OSDOMAINROLE == "none"){
  result = string("nicht zutreffend");
  desc = string("Das System ist kein Windows-Domaincontroller.");
}else if(MBSAALL >< "nosock"){
  result = string("Fehler");
   if (!log) desc = string('Beim Testen des Systems wurde festgestellt,\ndass keine SSH Verbindung aufgebaut werden konnte.');
   if (log) desc = string("Beim Testen des Systems trat beim Verbinden über SSH ein Fehler auf: " + log);
}else if(MBSAALL >< "none"){
  result = string("Fehler");
  desc = string('Beim Testen des Systems wurde festgestellt,\ndass SLAD keine Ergebnisse geliefert hat.');
}else if(MBSAALL =~ "404 (P|p)lugin not found.*"){
  result = string("Fehler");
  desc = string('Beim Testen des Systems wurde festgestellt, dass das\nnotwendige MBSA-Plugin nicht installiert ist.');
}else if(MBSAALL >< "running" || MBSAALL >< "running" || "Still running processes" >< FASTJOHN){
  result = string("unvollständig");
  desc = string('Beim Testen des Systems wurde festgestellt, dass SLAD\nnocht nicht mit allen Tests fertig ist.\nBitte wiederholen Sie den Test später noch einmal.');
}else if("wsusscn2.cab and/or wuredist.cab has failed" >< MBSAALL){
  result = string("Fehler");
  desc = string('wsusscn2.cab und/oder wuredist.cab konnte von wget\nnicht herruntergeladen werden. Überprüfen Sie ggf. im\nwinslad Pluginverzeichnis mbsa, die runmbsa.bat, ob\nggf. die Proxyeinstellungen konfiguriert oder\nangepasst werden müssen.');
}else if("Sicherheitsbewertung: Schwerwiegendes Risiko" >< MBSAALL || "Security assessment: Severe Risk" >< MBSAALL || "Sicherheitsbewertung: Potenzielles Risiko" >< MBSAALL  || "Security assessment: Potential Risk" >< MBSAALL){
  result = string("nicht erfüllt");
  desc = MBSAALLERR;
}else if("Sicherheitsbewertung: Verstärkte Sicherheit" >< MBSAALL || "Security assessment: Strong Security" >< MBSAALL){
  result = string("erfüllt");
  desc = MBSAALLERR;
}else if("Sie verfügen nicht über ausreichende Berechtigungen, um diesen Befehl auszuführen." >< MBSAALL || "You do not have sufficient permissions to perform this command." >< MBSAALL){
  result = string("Fehler");
  desc = string('Sie haben nicht genügend Rechte auf dem System. Das\nProblem taucht in der Regel unter Windows Vista und\nWindows 7 bei aktiviertem UAC auf.\n') + MBSAALL;
}else if("Microsoft Baseline Security Analyzer 2 maybe not installed!" >< MBSAALL){
  result = string("Fehler");
  desc = string('Microsoft Baseline Security Analyzer 2 ist auf dem\nSystem nicht installiert.');;
}else if("You do not have sufficient permissions!" >< MBSAALL){
  result = string("Fehler");
  desc = string('Sie haben nicht genügend Rechte auf dem System. Das\nProblem taucht unter Windows Vista und Windows 7 bei\naktiviertem UAC auf');;
}else if("Computer has an older version of the client and security database demands a newer version." >< MBSAALL || "Auf dem Computer wird eine ältere Clientversion ausgeführt. Die Sicherheitsdatenbank erfordert eine neuere Version." >< MBSAALL){
  result = string("Fehler");
  desc = MBSAALL;
}else if("0x800704dd" >< MBSAALL){
  result = string("Fehler");
  desc = string('Beim Testen des Systems wurde Fehler 0x800704dd fest-\ngestellt. Sie sollten den Windows Update Client\naktuallisieren.');
}else if("noslad" >< MBSAALL) {
  result = string("Fehler");
  desc = string('Anscheinend ist SLAD nicht installiert oder falsch\nkonfiguriert.');
}else{
  result = string("Fehler");
  desc = string('Ein unbekanntes Ergebnis ist aufgetreten:') + MBSAALL;
}

if (OSDOMAINROLE >= 4 && OSDOMAINROLE != "none"){
  if (MBSAALLERR){
    if (result == "erfüllt")  desc = MBSAALLERR;
    result = "nicht erfüllt"; 
  }
  Lst = split(FASTJOHN, sep:"|", keep:0);
  for(i=0; i<max_index(Lst); i++){
    if ("NOPW=" >< Lst[i]){
      nopwuser = Lst[i] - "NOPW=";
    }  
    else if("WEAK=" >< Lst[i]){
      weakuser = Lst[i] - "WEAK=";
    }
  }
  if(nopwuser || weakuser){
      result = string("nicht erfüllt");
      desc += string('\nFolgende Benutzer entsprechen nicht den Anforderungen\ndes IT-Grundschutz-Katalogs:');
      if (nopwuser) desc += '\nKeine Passwort: ' + nopwuser;
#    if (nopwuser) desc += '\nUnsicheres Passwort: ' + weakuser;    
  }
}

set_kb_item(name:"GSHB-12/M4_315/result", value:result);
set_kb_item(name:"GSHB-12/M4_315/desc", value:desc);
set_kb_item(name:"GSHB-12/M4_315/name", value:name);

silence = get_kb_item("GSHB-12/silence");

if (silence){
exit(0);
} else {
  report = 'Ergebnisse zum IT-Grundschutz, 12. Ergänzungslieferung:\n\n';
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
