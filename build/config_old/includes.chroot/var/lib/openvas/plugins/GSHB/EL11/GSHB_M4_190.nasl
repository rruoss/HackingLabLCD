###############################################################################
# OpenVAS Vulnerability GSHB
# $Id: GSHB_M4_190.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 11. EL, Maﬂnahme 4.190
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
tag_summary = "IT-Grundschutz M4.190: Entfernen der RDS-Unterst¸tzung des IIS (Win)

  Diese Pr¸fung bezieht sich auf die 11. Erg‰nzungslieferung (11. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
  Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

  http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04190.html";


if(description)
{
  script_id(894190);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Thu Jan 14 14:29:35 2010 +0100");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.190: Entfernen der RDS-Unterst¸tzung des IIS (Win)");
  if (! OPENVAS_VERSION)
  {
    desc = "
    Leider setzen Sie einen zu alten OpenVAS Scan-Server ein.
    Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!";
    script_description(desc);
    script_summary("IT-Grundschutz M4.190: Entfernen der RDS-Unterst¸tzung des IIS (Win)");
    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
    script_family("IT-Grundschutz-11");
    exit(0);
  }
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("IT-Grundschutz M4.190: Entfernen der RDS-Unterst¸tzung des IIS (Win)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-11");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-11");
  script_dependencies("GSHB/GSHB_WMI_IIS_RDS.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  script_require_keys("WMI/RDSServer.DataFactory", "WMI/AdvancedDataFactory", "WMI/VbBusObj.VbBusObjCls");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.190: Entfernen der RDS-Unterst¸tzung des IIS (Win)\n';

if (! OPENVAS_VERSION)
{
        set_kb_item(name:"GSHB-11/M4_190/result", value:"nicht zutreffend");
        set_kb_item(name:"GSHB-11/M4_190/desc", value:"Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!");
        set_kb_item(name:"GSHB-11/M4_190/name", value:name);
    log_message(port:0, proto: "IT-Grundschutz", data:string("Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!"));  
    exit(0);
}


WMIOSLOG = get_kb_item("WMI/WMI_OS/log");
GSHB_4_190_1 = get_kb_item("WMI/RDSServer.DataFactory");
GSHB_4_190_2 = get_kb_item("WMI/AdvancedDataFactory");
GSHB_4_190_3 = get_kb_item("WMI/VbBusObj.VbBusObjCls");
log = get_kb_item("WMI/RDSServer/log");

gshbm = "GSHB Maﬂnahme 4.190: ";

if (WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System."){
  result = string("nicht zutreffend");
  desc = string("Auf dem System l‰uft Samba,\nes ist kein Microsoft Windows System.");
}else if (GSHB_4_190_1 >< "error" && GSHB_4_190_2 >< "error" && GSHB_4_190_3 >< "error"){
    result = string("Fehler");
    if (!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
    if (log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
} else if (GSHB_4_190_1 >< "inapplicable" && GSHB_4_190_2 >< "inapplicable" && GSHB_4_190_3 >< "inapplicable"){
    result = string("nicht zutreffend");
    desc = string("Das System wurde nicht getestet, da es anscheinend kein Windows-System ist.");
} else if(GSHB_4_190_1 >< "off" && GSHB_4_190_2 >< "off" && GSHB_4_190_3 >< "off"){
    result = string("erf¸llt");
    desc = string("Entfernen der RDS-Unterst¸tzung des IIS,\nist richtig konfiguriert.");
} else {
  if(GSHB_4_190_1 >< "off"){
                 GSHB_4_190_1_desc = string ("Entfernen der RDS-Unterst¸tzung (RDSServer.DataFactory\n) des IIS, ist richtig konfiguriert.\n");
      }else{
                 GSHB_4_190_1_desc = string ("Entfernen der RDS-Unterst¸tzung (RDSServer.DataFactory\n) des IIS, ist nicht richtig konfiguriert.\n");
     }
        if(GSHB_4_190_2 >< "off"){
                 GSHB_4_190_2_desc = string ("Entfernen der RDS-Unterst¸tzung (AdvancedDataFactory)\ndes IIS, ist richtig konfiguriert.\n");
            }else{
                 GSHB_4_190_2_desc = string ("Entfernen der RDS-Unterst¸tzung (AdvancedDataFactory)\ndes IIS, ist nicht richtig konfiguriert.\n");
                 }
        if(GSHB_4_190_3 >< "off"){
                 GSHB_4_190_3_desc = string ("Entfernen der RDS-Unterst¸tzung (VbBusObj.VbBusObjCls)\ndes IIS, ist richtig konfiguriert.\n");
            }else{
                 GSHB_4_190_3_desc = string ("Entfernen der RDS-Unterst¸tzung (VbBusObj.VbBusObjCls)\ndes IIS, ist nicht richtig konfiguriert.\n");
                 }
result = string("nicht erf¸llt");
desc += GSHB_4_190_1_desc;
desc += GSHB_4_190_2_desc;
desc += GSHB_4_190_3_desc;
      }

set_kb_item(name:"GSHB-11/M4_190/result", value:result);
set_kb_item(name:"GSHB-11/M4_190/desc", value:desc);
set_kb_item(name:"GSHB-11/M4_190/name", value:name);

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
