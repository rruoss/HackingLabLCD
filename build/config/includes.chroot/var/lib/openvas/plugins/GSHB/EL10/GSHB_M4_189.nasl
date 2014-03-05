###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_189.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 10. EL, Maﬂnahme 4.189
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
tag_summary = "IT-Grundschutz M4.189: Schutz vor unzul‰ssigen Programmaufrufen beim IIS-Einsatz.

  Diese Pr¸fung bezieht sich auf die 10. Erg‰nzungslieferung (10. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
  Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

  http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04189.html";


if(description)
{
  script_id(94189);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Thu Jan 14 14:29:35 2010 +0100");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.189: Schutz vor unzul‰ssigen Programmaufrufen beim IIS-Einsatz (Win)");
  if (! OPENVAS_VERSION)
  {
    desc = "
    Leider setzen Sie einen zu alten OpenVAS Scan-Server ein.
    Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!";
    script_description(desc);
    script_summary("IT-Grundschutz M4.189: Schutz vor unzul‰ssigen Programmaufrufen beim IIS-Einsatz.");
    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
    script_family("IT-Grundschutz-10");
    exit(0);
  }
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("IT-Grundschutz M4.189: Schutz vor unzul‰ssigen Programmaufrufen beim IIS-Einsatz.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-10");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-10");
  script_dependencies("GSHB/GSHB_IIS_metabase.nasl","GSHB/GSHB_WMI_IIS_exec_cmd.nasl" );
#  script_require_keys("GSHB/AspEnableParentPaths", "WMI/SSIEnableCmdDirective", "GSHB/GSHB_WMI_OSInfo.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.189: Schutz vor unzul‰ssigen Programmaufrufen beim IIS-Einsatz (Win)\n';

if (! OPENVAS_VERSION)
{
        set_kb_item(name:"GSHB-10/M4_189/result", value:"nicht zutreffend");
        set_kb_item(name:"GSHB-10/M4_189/desc", value:"Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!");
        set_kb_item(name:"GSHB-10/M4_189/name", value:name);
    log_message(port:0, proto: "IT-Grundschutz", data:string("Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!"));  
    exit(0);
}



iismeta = get_kb_item("GSHB/AspEnableParentPaths");
iisaspencmd = get_kb_item("WMI/SSIEnableCmdDirective");
log = get_kb_item("WMI/SSIEnableCmdDirective/log");
WMIOSLOG = get_kb_item("WMI/WMI_OS/log");
gshbm =  "IT-Grundschutz M4.189: ";

if (WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System."){
  result = string("nicht zutreffend");
  desc = string("Auf dem System l‰uft Samba, es ist kein Microsoft System.");
}else if(iisaspencmd >< "off" && iismeta >< "none" || !iismeta){
  result = string("nicht zutreffend");
  desc = string("Auf dem System ist kein IIS installiert.");
} else if(iisaspencmd >< "inapplicable" && iismeta >< "inapplicable"){
  result = string("nicht zutreffend");
  desc = string("Das Systems wurde nicht getestet, da es anscheinend kein Windows System ist.");
} else if(iisaspencmd >< "error" || iismeta >< "error"){
  result = string("Fehler");
  if (!log) desc = string("Beim Testen des Systems trat ein Fehler auf, siehe Log Message!");
  if (log) desc = string("Beim Testen des Systems trat ein Fehler auf: " + log);
} else if(iisaspencmd >< "off" && iismeta >< "off"){
  result = string("erf¸llt");
  desc = string("Exec Aufrufes und die Option '¸bergeordneten Pfade des IIS f¸r ASP Scripte' sind deaktiviert");
} else if(iisaspencmd >< "on" && iismeta >< "off"){
  result = string("nicht erf¸llt");
  desc = string("Exec Aufrufes des IIS ist NICHT deaktiviert.\n") + string("Die Option '¸bergeordneten Pfade des IIS f¸r ASP Scripte' ist deaktiviert!");
} else if(iisaspencmd >< "off" && iismeta >< "on"){
  result = string("nicht erf¸llt");
  desc = string("Exec Aufrufes des IIS ist deaktiviert.\n") + string("Die Option ¸bergeordneten Pfade des IIS f¸r ASP Scripte ist NICHT deaktiviert!\n") + string("Nach dem ‰ndern der Option '¸bergeordneten Pfade des IIS f¸r ASP Scripte', bitte den IIS vor dem n‰chsten Test neu starten.");
} else {
  result = string("nicht erf¸llt");
  desc = string("Exec Aufrufes des IIS ist NICHT deaktiviert.\n") + string("Die Option ¸bergeordneten Pfade des IIS f¸r ASP Scripte ist NICHT deaktiviert!\n") + string("Nach dem ‰ndern der Option '¸bergeordneten Pfade des IIS f¸r ASP Scripte', bitte den IIS vor dem n‰chsten Test neu starten.");
}

set_kb_item(name:"GSHB-10/M4_189/result", value:result);
set_kb_item(name:"GSHB-10/M4_189/desc", value:desc);
set_kb_item(name:"GSHB-10/M4_189/name", value:name);

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
