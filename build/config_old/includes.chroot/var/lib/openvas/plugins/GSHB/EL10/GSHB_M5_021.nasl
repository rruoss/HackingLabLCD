###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M5_021.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 10. EL, Maﬂnahme 5.021
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
tag_summary = "IT-Grundschutz M5.021: Sicherer Einsatz von telnet, ftp, tftp und rexec.

  Diese Pr¸fung bezieht sich auf die 10. Erg‰nzungslieferung (10. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
  Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

  http://www.bsi.bund.de/grundschutz/kataloge/m/m05/m05021.html";

if(description)
{
  script_id(95021);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Wed May 05 15:06:40 2010 +0200");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M5.021: Sicherer Einsatz von telnet, ftp, tftp und rexec");
  
  if (! OPENVAS_VERSION)
  {
    desc = "Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers.";
    script_description(desc);
    script_summary("IT-Grundschutz M5.021: Sicherer Einsatz von telnet, ftp, tftp und rexec");
    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
    script_family("IT-Grundschutz-10");
    exit(0);
  }
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("IT-Grundschutz M5.021: Sicherer Einsatz von telnet, ftp, tftp und rexec.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-10");
  script_mandatory_keys("Compliance/Launch/GSHB-10");
  script_dependencies ("GSHB/GSHB_SSH_r-tools.nasl", "GSHB/GSHB_WMI_OSInfo.nasl", "GSHB/GSHB_TFTP_s-option.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M5.021: Sicherer Einsatz von telnet, ftp, tftp und rexec\n';



if (! OPENVAS_VERSION)
  {
        set_kb_item(name:"GSHB-10/M5_021/result", value:"nicht zutreffend");
        set_kb_item(name:"GSHB-10/M5_021/desc", value:"Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers.");
        set_kb_item(name:"GSHB-10/M5_021/name", value:name);
    log_message(port:0, proto: "IT-Grundschutz", data:string("Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers."));  
    exit(0);
}

gshbm =  "IT-Grundschutz M5.021: ";

OSNAME = get_kb_item("WMI/WMI_OSNAME");

inetdconf = get_kb_item("GSHB/R-TOOL/inetdconf");
ftpusers = get_kb_item("GSHB/R-TOOL/ftpusers");
netrc = get_kb_item("GSHB/R-TOOL/netrc");
log = get_kb_item("GSHB/R-TOOL/log");
tftp = get_kb_item("GSHB/TFTP/s-option");

if (inetdconf >!< "noentry" && inetdconf >!< "none"){
  Lst = split(inetdconf, keep:0);
  for(i=0; i<max_index(Lst); i++){
    if (Lst[i] =~ "^ftp.*") val_ftp = "yes";
    if (Lst[i] =~ "^tftp.*") val_tftp = "yes";
    if (Lst[i] =~ "^telnet.*") val_telnet = "yes";    
  }
}

if(OSNAME >!< "none"){
  result = string("nicht zutreffend");
  desc = string('Dieser Test bezieht sich auf UNIX/LINUX Systeme. Das System ist ein ' + OSNAME + ' System.');
}else if(inetdconf == "windows") {
    result = string("nicht zutreffend");
    desc = string('Dieser Test bezieht sich auf UNIX/LINUX Systeme. Das System scheint ein Windows-System zu sein.');
}else if(rhosts == "error"){
  result = string("Fehler");
  if(!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
  if(log) desc = string("Beim Testen des Systems trat ein Fehler auf: " + log);
}else if (netrc != "not found" || val_tftp == "yes" || tftp == "fail" || val_telnet == "yes" || (val_ftp == "yes" && ftpusers == "noentry")){
  result = string("nicht erf¸llt");
  if (netrc != "not found")desc = string('Es muss sichergestellt werden, dass keine .netrc-Dateien in den Benutzerverzeichnissen vorhanden\nsind oder dass sie leer sind und der Benutzer keine Zugriffsrechte auf diese hat.\nFolgende .netrc-Dateien wurden gefunden:\n' + netrc);
  if (val_tftp == "yes") desc += string('\nDer Einsatz des Daemons tftpd muss verhindert werden (z. B. durch Entfernen\ndes entsprechenden Eintrags in der Datei /etc/inetd.conf).');
  if (val_ftp == "yes") desc += string('\nF¸hren Sie bitte einen NVT-Scan aus, um mˆgliche Sicherheitsl¸cken im installierten FTP-Server zu finden.');
  if (val_ftp == "yes" && ftpusers == "noentry")desc += string('\nEs konnten keine Eintr‰ge in der Datei -/etc/ftpusers- gefunden werden.\nIn die Datei /etc/ftpusers sollten alle Benutzernamen eingetragen werden, f¸r die ein ftp-Zugang\nnicht erlaubt werden soll. Hierzu gehˆren z. B. root, uucp und bin.');
  if (val_ftp == "yes" && ftpusers != "none")desc += string('\nIn die Datei /etc/ftpusers sollten alle Benutzernamen eingetragen werden, f¸r die ein\nftp-Zugang nicht erlaubt werden soll. Hierzu gehˆren z. B. root, uucp und bin.\nFolgende Eintr‰ge wurden in der Datei -/etc/ftpusers- gefunden: \n' + ftpusers);  
  if (val_telnet == "yes") desc += string('\nAuf dem Zilesystem wurde ein Telnet-Server in der -/etc/inetd.conf- gefunden.\nSie sollten SSH anstelle von telnet nutzen.');
  if (tftp == "fail") desc += string('Es muss sichergestellt sein, dass beim Einsatz von tftp den Benutzern aus dem Login-Verzeichnis\nnur eingeschr‰nkte Dateizugriffe mˆglich sind. In diesem Fall war es mˆglich auf die Datei\n-/etc/passwd- zuzugreifen. Starten Sie den tftp-Daemon mit der Option -s verzeichnis.');
}else{
  result = string("erf¸llt");
  desc = string("Das System entspricht der Maﬂnahme 5.021.");
  if (val_ftp == "yes") desc += string('\nF¸hren Sie bitte einen NVT-Scan aus, um mˆgliche Sicherheitsl¸cken im installierten FTP-Server zu finden.');
  if (val_ftp == "yes" && ftpusers != "none")desc += string('\n\nIn die Datei /etc/ftpusers sollten alle Benutzernamen eingetragen werden, f¸r die ein\nftp-Zugang nicht erlaubt werden soll. Hierzu gehˆren z. B. root, uucp und bin.\nFolgende Eintr‰ge wurden in der Datei -/etc/ftpusers- gefunden: \n' + ftpusers);
}


if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler auf bzw. es konnte kein Ergebnis ermittelt werden.'); 
}

set_kb_item(name:"GSHB-10/M5_021/result", value:result);
set_kb_item(name:"GSHB-10/M5_021/desc", value:desc);
set_kb_item(name:"GSHB-10/M5_021/name", value:name);

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
