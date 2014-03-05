###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M5_101.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 11. EL, Maﬂnahme 5.101
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
tag_summary = "IT-Grundschutz M5.101: Entfernen nicht benˆtigter ODBC-Treiber beim IIS-Einsatz (Win).

  Diese Pr¸fung bezieht sich auf die 11. Erg‰nzungslieferung (11. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
  Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

  http://www.bsi.bund.de/grundschutz/kataloge/m/m05/m05101.html";


if(description)
{
  script_id(895101);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Thu Jan 14 14:29:35 2010 +0100");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M5.101: Entfernen nicht benˆtigter ODBC-Treiber beim IIS-Einsatz (Win)");
  if (! OPENVAS_VERSION)
  {
    desc = "
    Leider setzen Sie einen zu alten OpenVAS Scan-Server ein.
    Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!";
    script_description(desc);
    script_summary("IT-Grundschutz M5.101: Entfernen nicht benˆtigter ODBC-Treiber beim IIS-Einsatz (Win).");
    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
    script_family("IT-Grundschutz-11");
    exit(0);
  }
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("IT-Grundschutz M5.101: Entfernen nicht benˆtigter ODBC-Treiber beim IIS-Einsatz (Win).");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-11");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-11");
  script_dependencies("GSHB/GSHB_WMI_get_ODBCINST.nasl", "GSHB/GSHB_WMI_IIS_OpenPorts.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  script_require_keys("WMI/IISandPorts", "WMI/ODBCINST");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M5.101: Entfernen nicht benˆtigter ODBC-Treiber beim IIS-Einsatz (Win)\n';

if (! OPENVAS_VERSION)
{
        set_kb_item(name:"GSHB-11/M5_101/result", value:"nicht zutreffend");
        set_kb_item(name:"GSHB-11/M5_101/desc", value:"Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!");
        set_kb_item(name:"GSHB-11/M5_101/name", value:name);
    log_message(port:0, proto: "IT-Grundschutz", data:string("Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!"));  
    exit(0);
}


gshbm =  "IT-Grundschutz M5.101: ";

IISVER = get_kb_item("WMI/IISandPorts");
ODBC = get_kb_item("WMI/ODBCINST");
log = get_kb_item("WMI/ODBCINST/log");
iislog = get_kb_item("WMI/IISandPorts/log");
WMIOSLOG = get_kb_item("WMI/WMI_OS/log");

if (WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System."){
  result = string("nicht zutreffend");
  desc = string("Auf dem System l‰uft Samba, es ist kein Microsoft System.");
}else if("error" >< ODBC){
  result = string("Fehler");
  if (!log && !iislog) desc = string("Beim Testen des Systems trat ein Fehler auf.");
  else if (log || iislog){
    if (log >< iislog) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);  
    else desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log + '\n' + iislog);  
  }
}else if("None" >< IISVER){
  result = string("nicht zutreffend");
  desc = string("Auf dem System ist kein IIS installiert.");
}else if("None" >!< IISVER && "None" >< ODBC){
  result = string("erf¸llt");
  desc = string('Auf dem System wurden keine ODBC-Schnittstellen gefunden.');
}else{
  result = string("nicht erf¸llt");
  desc = string("Folgende ODBC-Schnittstellen befinden sich noch auf dem System:" + '\n' + ODBC);
}

set_kb_item(name:"GSHB-11/M5_101/result", value:result);
set_kb_item(name:"GSHB-11/M5_101/desc", value:desc);
set_kb_item(name:"GSHB-11/M5_101/name", value:name);

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
