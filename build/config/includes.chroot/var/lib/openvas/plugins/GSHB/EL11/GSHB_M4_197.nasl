###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_197.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 11. EL, Maﬂnahme 4.197
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
tag_summary = "IT-Grundschutz M4.197: Servererweiterungen f¸r dynamische Webseiten beim Apache-Webserver (Win).

  Diese Pr¸fung bezieht sich auf die 11. Erg‰nzungslieferung (11. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
  Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

  http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04197.html";


if(description)
{
  script_id(894197);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Thu Jan 14 14:29:35 2010 +0100");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.197: Servererweiterungen f¸r dynamische Webseiten beim Apache-Webserver (Win)");
  if (! OPENVAS_VERSION)
  {
    desc = "
    Leider setzen Sie einen zu alten OpenVAS Scan-Server ein.
    Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!";
    script_description(desc);
    script_summary("IT-Grundschutz M4.197: Servererweiterungen f¸r dynamische Webseiten beim Apache-Webserver (Win).");
    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
    script_family("IT-Grundschutz-11");
    exit(0);
  }
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("IT-Grundschutz M4.197: Servererweiterungen f¸r dynamische Webseiten beim Apache-Webserver (Win).");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-11");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-11");
  script_dependencies("GSHB/GSHB_WMI_Apache.nasl","GSHB/GSHB_Read_Apache_Config.nasl","GSHB/GSHB_WMI_Apache_ScriptAlias.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  script_require_keys("WMI/Apache");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.197: Servererweiterungen f¸r dynamische Webseiten beim Apache-Webserver (Win)\n';

if (! OPENVAS_VERSION)
{
        set_kb_item(name:"GSHB-11/M4_197/result", value:"nicht zutreffend");
        set_kb_item(name:"GSHB-11/M4_197/desc", value:"Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!");
        set_kb_item(name:"GSHB-11/M4_197/name", value:name);
    log_message(port:0, proto: "IT-Grundschutz", data:string("Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!"));  
    exit(0);
}


gshbm =  "IT-Grundschutz M4.197: ";
WMIOSLOG = get_kb_item("WMI/WMI_OS/log");
AP = get_kb_item("WMI/Apache");
APCGIFILES = get_kb_item("WMI/Apache/CGIFileList");
APCGIINDOC = get_kb_item("WMI/Apache/CGIinDOCPath");
APCGIINDOCSUM = get_kb_item("WMI/Apache/CGIinDOCPathSum");
APLMCGI = get_kb_item("WMI/Apache/LoadModul_LMCGI");
APLMINC = get_kb_item("WMI/Apache/LoadModul_LMINC");
APLMISAPI = get_kb_item("WMI/Apache/LoadModul_LMISAPI");
APLMPERL = get_kb_item("WMI/Apache/LoadModul_LMPERL");
APLMPHP = get_kb_item("WMI/Apache/LoadModul_LMPHP");
APLMPHP3 = get_kb_item("WMI/Apache/LoadModul_LMPHP3");
APLMPHP4 = get_kb_item("WMI/Apache/LoadModul_LMPHP4");
APLMJK = get_kb_item("WMI/Apache/LoadModul_LMJK");
log = get_kb_item("GSHB/ApacheConfig/log");

if (WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System."){
  result = string("nicht zutreffend");
  desc = string("Auf dem System l‰uft Samba,\nes ist kein Microsoft Windows System.");
}else if("error" >< AP){
  result = string("Fehler");
  if (!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
  if (log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" +  log);
}else if("false" >< AP){
  result = string("nicht zutreffend");
  desc = string("Auf dem System ist kein Apache installiert.");
}
else
{
  if (APCGIINDOC >< "FALSE")
  {
    result = string("erf¸llt");
    desc = string('Es befindet sich kein CGI-Alias-Verzeichnis im\nWWW-Root.\n');
    if (APLMCGI >!< "None") desc = desc + string("Folgendes Modul wird geladen: ") + APLMCGI + '\n';
    if (APLMINC >!< "None") desc = desc + string("Folgendes Modul wird geladen: ") + APLMINC + '\n';
    if (APLMISAPI >!< "None") desc = desc + string("Folgendes Modul wird geladen: ") + APLMISAPI + '\n';
    if (APLMPERL >!< "None") desc = desc + string("Folgendes Modul wird geladen: ") + APLMPERL + '\n';
    if (APLMPHP >!< "None") desc = desc + string("Folgendes Modul wird geladen: ") + APLMPHP + '\n';
    if (APLMPHP3 >!< "None") desc = desc + string("Folgendes Modul wird geladen: ") + APLMPHP3 + '\n';
    if (APLMPHP4 >!< "None") desc = desc + string("Folgendes Modul wird geladen: ") + APLMPHP4 + '\n';
    if (APLMJK >!< "None") desc = desc + string("Folgendes Modul wird geladen: ") + APLMJK + '\n';
  }
  else
  {
    result = string("nicht erf¸llt");
    desc = string('Es befindet sich mindests ein CGI-Alias-Verzeichnis\nim WWW-Root:\n') + APCGIINDOC + '\n';
    desc = desc + string('Folgende(s) Verzeichnis(se) existiert/existieren davon\nim Dateisystem:\n') + APCGIINDOCSUM + '\n';
    desc = desc + string('Folgende Dateien existieren in den CGI-Alias\nVerzeichnissen:\n') + APCGIFILES + '\n';
    if (APLMCGI >!< "None") desc = desc + string("Folgendes Modul wird geladen: ") + APLMCGI + '\n';
    if (APLMINC >!< "None") desc = desc + string("Folgendes Modul wird geladen: ") + APLMINC + '\n';
    if (APLMISAPI >!< "None") desc = desc + string("Folgendes Modul wird geladen: ") + APLMISAPI + '\n';
    if (APLMPERL >!< "None") desc = desc + string("Folgendes Modul wird geladen: ") + APLMPERL + '\n';
    if (APLMPHP >!< "None") desc = desc + string("Folgendes Modul wird geladen: ") + APLMPHP + '\n';
    if (APLMPHP3 >!< "None") desc = desc + string("Folgendes Modul wird geladen: ") + APLMPHP3 + '\n';
    if (APLMPHP4 >!< "None") desc = desc + string("Folgendes Modul wird geladen: ") + APLMPHP4 + '\n';
    if (APLMJK >!< "None") desc = desc + string("Folgendes Modul wird geladen: ") + APLMJK + '\n';
  }

}


set_kb_item(name:"GSHB-11/M4_197/result", value:result);
set_kb_item(name:"GSHB-11/M4_197/desc", value:desc);
set_kb_item(name:"GSHB-11/M4_197/name", value:name);

silence = get_kb_item("GSHB-11/silence");

if (silence){
exit(0);
} else {
  report = 'Ergebnisse zum IT-Grundschutz, 11. Erg‰nzungslieferung:\n\n';
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
