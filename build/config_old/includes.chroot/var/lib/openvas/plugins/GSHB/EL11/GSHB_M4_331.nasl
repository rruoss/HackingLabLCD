##############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_331.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 11. EL, Maﬂnahme 4.331
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
tag_summary = "IT-Grundschutz M4.331: Sichere Konfiguration des Betriebssystems f¸r einen Samba-Server

  Diese Pr¸fung bezieht sich auf die 11. Erg‰nzungslieferung (11. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
  Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

  http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04331.html";


if(description)
{
  script_id(894331);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Thu May 27 16:54:06 2010 +0200");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.331: Sichere Konfiguration des Betriebssystems f¸r einen Samba-Server");
  if (! OPENVAS_VERSION)
  {
    desc = "
    Leider setzen Sie einen zu alten OpenVAS Scan-Server ein.
    Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!";
    script_description(desc);
    script_summary("IT-Grundschutz M4.331: Sichere Konfiguration des Betriebssystems f¸r einen Samba-Server");
    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
    script_family("IT-Grundschutz-11");
    exit(0);
  }
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("IT-Grundschutz M4.331: Sichere Konfiguration des Betriebssystems f¸r einen Samba-Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-11");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-11");
  script_dependencies("GSHB/GSHB_SSH_fstab.nasl","netbios_name_get.nasl", "GSHB/GSHB_SSH_SAMBA_ntfs_ACL_ADS.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.331: Sichere Konfiguration des Betriebssystems f¸r einen Samba-Server\n';

if (! OPENVAS_VERSION)
{
        set_kb_item(name:"GSHB-11/M4_331/result", value:"nicht zutreffend");
        set_kb_item(name:"GSHB-11/M4_331/desc", value:"Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!");
        set_kb_item(name:"GSHB-11/M4_331/name", value:name);
    log_message(port:0, proto: "IT-Grundschutz", data:string("Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!"));  
    exit(0);
}

samba = get_kb_item("SMB/samba");
NTFSADS = get_kb_item("GSHB/SAMBA/NTFSADS");
ACL = get_kb_item("GSHB/SAMBA/ACL");
ACLSUPP = get_kb_item("GSHB/SAMBA/ACLSUPP");
VER = get_kb_item("GSHB/SAMBA/VER");
reiserfs = get_kb_item("GSHB/FSTAB/reiserfs");
log = get_kb_item("GSHB/FSTAB/log");

if(!samba){
    result = string("nicht zutreffend");
    desc = string('Auf dem System l‰uft kein Samba-Dateiserver.');
}else if(reiserfs == "error"){
  result = string("Fehler");
  if (!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
  if (log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log); 
}else if(reiserfs == "noreiserfs" && ACL != "no" && ACLSUPP != "no" && NTFSADS != "no"){
    result = string("erf¸llt");
    desc = string('Auf dem System l‰uft keine Partition mit ReiserFS.\nNTFS Access Control Lists und NTFS Alternate Data\nStreams wurde richtig konfiguriert.\nBitte pr¸fen Sie\nob bei den aufgef¸hrten Mountpoints noch welche\nfehlen. Wenn ja, aktivieren Sie auch dort den ACL\nSupport.\n' + ACL + '\n \n');
    desc += string('Bitte pr¸fen Sie auch, ob am lokalen Paketfilter nur\ndie TCP und UDP Ports frei geschaltet, die f¸r den\nBetrieb des Samba-Servers nˆtig sind.');
}else if (reiserfs != "noreiserfs" || ACL == "no" || ACLSUPP == "no" || NTFSADS == "no"){
    result = string("nicht erf¸llt");
    if (reiserfs != "noreiserfs") desc = string('Auf dem System l‰uft folgende Partition mit ReiserFS:\n' + reiserfs +'\nS‰mtliche Samba-Datenbanken im TDB-Format sollten auf\neiner Partition gespeichert werden, die nicht ReiserFS\nals Dateisystem verwendet.\n \n');
    if (ACLSUPP == "no")desc += string('Der Konfigurationsparameter -nt acl support- in der\nKonfigurationsdatei smb.conf steht nicht auf -yes-.\n \n');
    if (ACL == "no")desc += string('Es wurde in /etc/fstab keine Unterst¸tzung f¸r ACL\ngefunden. Sie m¸ssen die ACL-Unterst¸tzung explizit\naktivieren.\n \n');
    if (NTFSADS == "no")desc += string('Sie setzen Samba Version ' + VER + ' ein.\nSamba 3.0.x bietet keine Mˆglichkeit NTFS ADS\nabzubilden. Samba 3.2.x und hˆher kann NTFS ADS direkt\nber POSIX Extended Attributes (xattr) abbilden.\n \n');
    desc += string('Bitte pr¸fen Sie auch, ob am lokalen Paketfilter nur\ndie TCP und UDP Ports frei geschaltet, die f¸r den\nBetrieb des Samba-Servers nˆtig sind.');
}



if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler\nauf bzw. es konnte kein Ergebnis ermittelt werden.'); 
}

set_kb_item(name:"GSHB-11/M4_331/result", value:result);
set_kb_item(name:"GSHB-11/M4_331/desc", value:desc);
set_kb_item(name:"GSHB-11/M4_331/name", value:name);

silence = get_kb_item("GSHB-11/silence");

if (silence){
exit(0);
} else {
  report = 'Ergebnisse zum IT-Grundschutz, 11. Erg‰nzungslieferung:\n \n';
  report = report + name + 'Ergebnis:\t' + result +
           '\nDetails:\t' + desc + '\n \n';
    if ("nicht erf¸llt" >< result || result >< "Fehler"){
    security_hole(port:0, proto: "IT-Grundschutz", data:report);
    } else if (result >< "unvollst‰ndig"){
    security_warning(port:0, proto: "IT-Grundschutz", data:report);
    } else if (result >< "erf¸llt" || result >< "nicht zutreffend"){
    security_note(port:0, proto: "IT-Grundschutz", data:report);
    }
exit(0);
}
