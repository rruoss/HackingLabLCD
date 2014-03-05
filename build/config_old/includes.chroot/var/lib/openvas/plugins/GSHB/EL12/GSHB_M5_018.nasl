###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M5_018.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 12. EL, Maﬂnahme 5.018
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
tag_summary = "IT-Grundschutz M5.018: Einsatz der Sicherheitsmechanismen von NIS.

Diese Pr¸fung bezieht sich auf die 12. Erg‰nzungslieferung (12. EL) des IT-
Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

http://www.bsi.bund.de/grundschutz/kataloge/m/m05/m05018.html";

if(description)
{
  script_id(95004);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2011-11-07 13:38:53 +0100 (Mon, 07 Nov 2011)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M5.018: Einsatz der Sicherheitsmechanismen von NIS");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("IT-Grundschutz M5.018: Einsatz der Sicherheitsmechanismen von NIS.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-12");
  script_mandatory_keys("Compliance/Launch/GSHB-12");
  script_dependencies ("GSHB/GSHB_WMI_OSInfo.nasl", "GSHB/GSHB_SSH_NIS.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M5.018: Einsatz der Sicherheitsmechanismen von NIS\n';

gshbm =  "IT-Grundschutz M5.018: ";

OSNAME = get_kb_item("WMI/WMI_OSNAME");

server = get_kb_item("GSHB/NIS/server");
client = get_kb_item("GSHB/NIS/client");
ypbind = get_kb_item("GSHB/NIS/ypbind");
ypserv = get_kb_item("GSHB/NIS/ypserv");
NisPlusUserwopw = get_kb_item("GSHB/NIS/NisPlusUserwopw");
NisPlusGenUserwopw = get_kb_item("GSHB/NIS/NisPlusGenUserwopw");
NisPlusUserwpw = get_kb_item("GSHB/NIS/NisPlusUserwpw");
NisPlusGenUserwpw = get_kb_item("GSHB/NIS/NisPlusGenUserwpw");
LocalUID0 = get_kb_item("GSHB/NIS/LocalUID0");
NisPlusGroupwopw = get_kb_item("GSHB/NIS/NisPlusGroupwopw");
NisPlusGenGroupwopw = get_kb_item("GSHB/NIS/NisPlusGenGroupwopw");
NisPlusGroupwpw = get_kb_item("GSHB/NIS/NisPlusGroupwpw");
NisPlusGenGroupwpw = get_kb_item("GSHB/NIS/NisPlusGenGroupwpw");
hostsdeny = get_kb_item("GSHB/NIS/hostsdeny");
hostsallow = get_kb_item("GSHB/NIS/hostsallow");
securenets = get_kb_item("GSHB/NIS/securenets");
log = get_kb_item("GSHB/NIS/log");

if ((server == "windows" && client == "windows") || (server == "error" && client == "error" && OSNAME != "none")){
    result = string("nicht zutreffend");
    if (OSNAME == "none") desc = string('Auf dem System l‰uft kein NIS (Network Information Service.');
    else desc = string('Auf dem System l‰uft kein NIS (Network Information Service),\nda es sich um ein\n' + OSNAME + '\nSystem handelt.');
}else if(server == "no" && client == "no" && ypbind == "no" && ypserv == "no" || ((client == "yes" && ypbind == "no") && (server == "yes" && ypserv == "no") ) ){

  if (NisPlusUserwopw == "yes" || NisPlusGenUserwopw == "yes" || NisPlusGenGroupwopw == "yes" || NisPlusGroupwopw == "yes" ){
    result = string("nicht erf¸llt");
    desc = string('Auf dem System l‰uft kein NIS (Network Information Service).\nAllerdings wurden NIS Eintr‰ge in Ihrer\n');
    if ((NisPlusUserwopw == "yes" || NisPlusGenUserwopw == "yes") && NisPlusGenGroupwopw == "no" && NisPlusGroupwopw == "no") desc += string(' -/etc/passwd- Datei gefunden.');
    else if (NisPlusUserwopw == "no" && NisPlusGenUserwpw == "no" && (NisPlusGenGroupwopw == "yes" || NisPlusGroupwopw == "yes")) desc += string(' -/etc/group- Datei gefunden.');
    else if (NisPlusUserwopw == "yes" && NisPlusGenUserwopw == "yes" && NisPlusGenGroupwopw == "yes" && NisPlusGroupwopw == "yes") desc += string(' -/etc/passwd- und -/etc/group- Datei gefunden.');
  }else {
    result = string("nicht zutreffend");
    desc = string('Auf dem System l‰uft kein NIS (Network Information Service).');
  }
}else if(server == "error"){
  result = string("Fehler");
  if(!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
  if(log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
}else if((server == "yes" &&  ypserv == "yes") || (client == "yes" && ypbind == "yes")){
  if (server == "yes" &&  ypserv == "yes"){
    if (NisPlusUserwopw == "yes" || NisPlusGroupwopw == "yes" || ((securenets == "everybody" || securenets == "none") && (hostsdeny == "noentry" || hostsallow == "noentry"))){
      result = string("nicht erf¸llt");
      if (NisPlusUserwopw == "yes") desc += string('\nIn der Passwortdatei -/etc/passwd- darf der Eintrag +::0:0:::\nnicht enthalten sein, da sonst ein Zugang mit dem Namen + ohne\nPasswort existiert.\nSollte der Eintrag notwendig sein, muss\ndas Passwort durch ein "*" ersetzt werden.');
      if (NisPlusGroupwopw == "yes") desc += string('\nIn der Gruppendatei -/etc/group- darf der Eintrag +::0: nicht\nenthalten sein,\nda sonst ein Zugang mit dem Namen + ohne\nPasswort existiert.\nSollte der Eintrag notwendig sein, muss\ndas Passwort durch ein "*" ersetzt werden.');
      if (securenets == "everybody" && (hostsdeny == "noentry" && hostsallow == "noentry"))desc += string('\nDer Server-Prozess ypserv sollte nur Anfragen von vorher fest-\ngelegten Rechnern beantworten.\nSie sollten Dazu die speziellen\nKonfigurationsdatei namens /etc/ypserv.securenet oder die\nDateien /etc/hosts.allow und /etc/hosts.deny bearbeiten.');
      else if ((securenets == "everybody" || securenets == "none") && (hostsallow != "noentry" && hostsdeny != "noentry")) desc += string('\nDer Server-Prozess ypserv sollte nur Anfragen von vorher fest-\ngelegten Rechnern beantworten. Sie sollten Dazu die speziellen\nKonfigurationsdatei namens /etc/ypserv.securenet bearbeiten.');
      else{
        if (hostsallow == "noentry" || hostsdeny == "noentry")desc += string('\nDer Server-Prozess ypserv sollte nur Anfragen von vorher fest-\ngelegten Rechnern beantworten.');
        if (hostsallow == "noentry" && hostsdeny != "noentry")desc += string('\nSie sollten Dazu die Datei /etc/hosts.allow bearbeiten. In der\nDatei /etc/hosts.deny wurde schon ein Eintrag gefunden:\n' + hostsdeny);
        else if (hostsdeny == "noentry" && hostsallow != "noentry")desc += string('\nSie sollten Dazu die Datei /etc/hosts.deny bearbeiten. In der\nDatei /etc/hosts.allow wurde schon ein Eintrag gefunden:\n' + hostsallow);
        else if (hostsallow == "noentry" && hostsdeny == "noentry") desc += string('\nSie sollten Dazu die Dateien /etc/hosts.allow und\n/etc/hosts.deny bearbeiten.');
      }
    }else{
      result = string("erf¸llt");
      desc = string('Die Einstellungen f¸r Ihren  NIS (Network Information Service)\nServer, entspechen den Empfehlungen der Maﬂnahme 5.018.');
    }
  }
  if (client == "yes" && ypbind == "yes" && (server == "no" || ypserv == "no")){
    if(NisPlusGenUserwopw == "yes" || NisPlusGenGroupwopw == "yes" || NisPlusUserwopw == "yes" || NisPlusGroupwopw == "yes" || LocalUID0 == "no" || LocalUID0 == "not first"){
      result = string("nicht erf¸llt");

      if (NisPlusUserwopw == "yes") desc += string('\nIn Ihrer Passwortdatei /etc/passwd wurde der Eintrag\n+::0:0::: gefunden.');
      if (NisPlusGroupwopw == "yes") desc += string('\nIn Ihrer Gruppendatei /etc/group wurde der Eintrag\n+::0: gefunden.');
      if (NisPlusGenUserwopw == "yes") desc += string('\nIn Ihrer Passwortdatei /etc/passwd wurde der Eintrag\n+:::::: gefunden.');
      if (NisPlusGenGroupwopw == "yes") desc += string('\nIn Ihrer Gruppendatei /etc/group wurde der Eintrag\n+::: gefunden.');
      if (NisPlusUserwopw == "yes" || NisPlusGroupwopw == "yes" || NisPlusGenUserwopw == "yes" || NisPlusGenGroupwopw == "yes")desc += string('\n\nEs muss auf jeden Fall ein Eintrag im Passwortfeld vorhanden\nsein, damit nicht im Falle einer (beabsichtigten oder nicht\nbeabsichtigten) Nichtbenutzung von NIS\nversehentlich ein\nZugang mit dem Benutzernamen + ohne Passwort geschaffen wird.');
      if (LocalUID0 == "no" || LocalUID0 == "not first") desc += string('\nUm zu verhindern, dass der NIS-Administrator auf allen NIS-\nClients root-Rechte hat, sollte auf jedem NIS-Client ein\nlokaler Benutzer mit der UID 0 eingerichtet werden.');
      if (LocalUID0 == "no") desc += string('\nAuf Ihrem System wurde kein solcher User gefunden.');
      else if (LocalUID0 == "not first") desc += string('\nAuf Ihrem System wurde zwar ein solcher User gefunden, dieser\nsollte aber vor dem -NIS User- mit der UID 0 stehen.');      
    }else{
      result = string("erf¸llt");
      desc = string('Die Einstellungen f¸r Ihren  NIS (Network Information Service)\nClient, entspechen den Empfehlungen der Maﬂnahme 5.018.');
      if (NisPlusUserwpw == "yes" || NisPlusGenUserwpw == "yes" ) desc += string('\nDer Eintrag +:*:0:0::: bzw. +:*::::: in der Passwortdatei\n/etc/passwd sollte dokumentiert werden.');
      if (NisPlusGroupwpw == "yes" || NisPlusGenGroupwpw == "yes") desc += string('\nDer Eintrag +:*:0 bzw. +:*: in der Passwortdatei /etc/passwd\nsollte dokumentiert werden.');      
    }
  }
}

if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler auf\nbzw. es konnte kein Ergebnis ermittelt werden.'); 
}

set_kb_item(name:"GSHB-12/M5_018/result", value:result);
set_kb_item(name:"GSHB-12/M5_018/desc", value:desc);
set_kb_item(name:"GSHB-12/M5_018/name", value:name);

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
