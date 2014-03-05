##############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_332.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 12. EL, Maﬂnahme 4.332
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
tag_summary = "IT-Grundschutz M4.332: Sichere Konfiguration der Zugriffssteuerung bei einem Samba-Server

Diese Pr¸fung bezieht sich auf die 12. Erg‰nzungslieferung (12. EL) des IT-
Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04332.html";


if(description)
{
  script_id(94086);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2011-11-07 13:38:53 +0100 (Mon, 07 Nov 2011)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.332: Sichere Konfiguration der Zugriffssteuerung bei einem Samba-Server");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("IT-Grundschutz M4.332: Sichere Konfiguration der Zugriffssteuerung bei einem Samba-Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-12");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-12");
  script_dependencies("toolcheck.nasl", "netbios_name_get.nasl", "GSHB/GSHB_SSH_SAMBA_ntfs_ACL_ADS.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.332: Sichere Konfiguration der Zugriffssteuerung bei einem Samba-Server\n';

if(!samba){
    result = string("nicht zutreffend");
    desc = string('Auf dem System l‰uft kein Samba-Dateiserver.');
}else if(NTFSADS == "error"){
  result = string("Fehler");
  if (!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
  if (log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log); 
}else if(ACL != "no" && ACLSUPP != "no" && NTFSADS != "no"){
    result = string("erf¸llt");
    desc = string('NTFS Access Control Lists und NTFS Alternate Data\nStreams wurde richtig konfiguriert. Bitte pr¸fen Sie\nob bei den aufgef¸hrten Mountpoints noch welche\nfehlen. Wenn ja, aktivieren Sie auch dort den\nACL Support.\n' + ACL +'\n \n');
    desc += string('- Sind die Administratoren damit vertraut, wie Samba\ndas Windows-Rechtemodell im Unix-Dateisystem abbildet?\n- Wissen die Administratoren, wie die Unix-Rechte f¸r\nneu erstellte Dateien zu Stande kommen?\n- Ist den Administratoren klar, wie sich das Entfernen\ndes DOS-Attibuts "Schreibschutz" auf die UNIX-Rechte\nauswirkt?\n- Wissen die Administratoren, dass die benutzer- und\ngruppenbezogenen Konfigurationsparameter die im Unix-\nDateisystem\ng¸ltigen Zugriffsberechtigungen f¸r\nBenutzer oder Gruppen ¸berschreiben?');
}else if (ACL == "no" || ACLSUPP == "no" || NTFSADS == "no"){
    result = string("nicht erf¸llt");
    if (ACLSUPP == "no")desc = string('Der Konfigurationsparameter -nt acl support- in der\nKonfigurationsdatei smb.conf steht nicht auf -yes-.\n \n');
    if (ACL == "no")desc += string('Es wurde in /etc/fstab keine Unterst¸tzung f¸r ACL\ngefunden. Sie m¸ssen die ACL-Unterst¸tzung explizit\naktivieren.\n \n');
    if (NTFSADS == "no")desc += string('Sie setzen Samba Version ' + VER + ' ein.\nSamba 3.0.x bietet keine Mˆglichkeit NTFS ADS\nabzubilden.\nSamba 3.2.x und hˆher kann NTFS ADS\ndirekt ber POSIX Extended Attributes (xattr) abbilden.');
}

if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler\nauf bzw. es konnte kein Ergebnis ermittelt werden.'); 
}

set_kb_item(name:"GSHB-12/M4_332/result", value:result);
set_kb_item(name:"GSHB-12/M4_332/desc", value:desc);
set_kb_item(name:"GSHB-12/M4_332/name", value:name);

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
