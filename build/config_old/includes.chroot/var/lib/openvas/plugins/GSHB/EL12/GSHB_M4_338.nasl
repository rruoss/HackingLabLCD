###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_338.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 12. EL, Maﬂnahme 4.338
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
tag_summary = "IT-Grundschutz M4.338: Einsatz von Windows Vista File und Registry VirtualizationWin).

Diese Pr¸fung bezieht sich auf die 12. Erg‰nzungslieferung (12. EL) des IT-
Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

Hinweis:

Nur ein genereller Test, ob Vista File und Registry Virtualization aktiviert ist.

http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04338.html";

if(description)
{
  script_id(94089);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2011-11-07 13:38:53 +0100 (Mon, 07 Nov 2011)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.338: Einsatz von Windows Vista File und Registry Virtualization (Win)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("IT-Grundschutz M4.338: Einsatz von Windows Vista File und Registry Virtualization (Win).");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-12");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-12");
  script_dependencies("GSHB/GSHB_WMI_OSInfo.nasl", "GSHB/GSHB_WMI_UAC_config.nasl");
  script_require_keys("WMI/UAC");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.338: Einsatz von Windows Vista File und Registry Virtualization (Win)\n';

gshbm =  "IT-Grundschutz M4.338: ";

OSVER = get_kb_item("WMI/WMI_OSVER");
OSTYPE = get_kb_item("WMI/WMI_OSTYPE");

EnableVirtualization = get_kb_item("WMI/EnableVirtualization");
EnableLUA = get_kb_item("WMI/EnableLUA");
UAC = get_kb_item("WMI/UAC");
log = get_kb_item("WMI/UAC/log");
WMIOSLOG = get_kb_item("WMI/WMI_OS/log");

if (WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System."){
  result = string("nicht zutreffend");
  desc = string("Auf dem System l‰uft Samba, es ist kein Microsoft System.");
}else if(UAC >< "error"){
  result = string("Fehler");
  if (!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
  if (log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
}else if(OSVER  >=  "6.0" && OSTYPE == "1"){

  if(EnableLUA != "1")
  {
    result = string("nicht erf¸llt");
    desc = string("User Access Control ist auf dem System deaktiviert, dadurch ist\nauch die Vista File und Registry Virtualization deaktiviert.");
  }
  else
  {
    if(EnableVirtualization == "1")
    {
      result = string("nicht erf¸llt");
      desc = string('Vista File und Registry Virtualization ist aktiviert. Beachten\nSie bitte die Hinweise im IT-Grundschutz-Katalog zur\nMaﬂnahme 4.338');
    }
    else
    {
        result = string("erf¸llt");
        desc = string("Vista File und Registry Virtualization ist deaktiviert.\nBeachten Sie bitte die Hinweise im IT-Grundschutz-Katalog zur\nMaﬂnahme 4.338");
    }
  } 
}else{
  result = string("nicht zutreffend");
  desc = string("Das System ist kein Microsoft Windows Vista System.");

}

set_kb_item(name:"GSHB-12/M4_338/result", value:result);
set_kb_item(name:"GSHB-12/M4_338/desc", value:desc);
set_kb_item(name:"GSHB-12/M4_338/name", value:name);

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
