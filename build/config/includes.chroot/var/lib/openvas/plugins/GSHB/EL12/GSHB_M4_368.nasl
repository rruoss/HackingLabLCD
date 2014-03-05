###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_368.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 12. EL, Maﬂnahme 4.368
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
tag_summary = "IT-Grundschutz M4.368: Regelm‰ﬂige Audits der Terminalserver-Umgebung.

Diese Pr¸fung bezieht sich auf die 12. Erg‰nzungslieferung (12. EL) des IT-
Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

Hinweis:

Es wird lediglich ein Meldung ausgegeben, dass mit aktuelleten Plugins getestet werden soll.

http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04368.html";


if(description)
{
  script_id(94100);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2011-12-14 11:38:53 +0100 (Wed, 14 Dec 2011)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.368: Regelm‰ﬂige Audits der Terminalserver-Umgebung");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("IT-Grundschutz M4.368: Regelm‰ﬂige Audits der Terminalserver-Umgebung.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-12");
  script_dependencies("GSHB/GSHB_WMI_TerminalServerSettings.nasl", "smb_nativelanman.nasl");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-12");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.368: Regelm‰ﬂige Audits der Terminalserver-Umgebung\n';

gshbm = "GSHB Maﬂnahme 4.368: ";

lanman = get_kb_item("SMB/NativeLanManager");

TSS = get_kb_item("WMI/TerminalService");
log = get_kb_item("WMI/TerminalService/log");
OSVER = get_kb_item("WMI/WMI_OSVER");

if (TSS != "error" && TSS != "none"){
  val = split(TSS,keep:0);
  val = split(val[1],sep:'|' ,keep:0);
}
if ("windows" >!< tolower(lanman)){
  result = string("nicht zutreffend");
  desc = string("Das System ist kein Windows Terminal Server. (Zur Zeit\nkann nur auf Windows Terminal Server getestet werden.)");
}else{

  if (!TSS){
    result = string("Fehler");
    desc = string("Bei Testen des Systems konnte kein Ergebnis ermittelt werden.");
  }
  else if ((OSVER != "none" && OSVER != "error") && TSS == "error"){
    result = string("Fehler");
    if (!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
    if (log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
  }
  else if ((OSVER != "none" && OSVER != "error") && TSS == "none"){
    result = string("nicht zutreffend");
    desc = string("Das System ist kein Windows Terminal Server. (Zur Zeit kann\nnur auf Windows Terminal Server getestet werden.)");
  }
  else if (TSS == "error"){
    result = string("Fehler");
    if (!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
    if (log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
  }
  else if (val[11] == "2" || val[11] == "4" || val[11] == "5"){
    result = string("unvollst‰ndig");
    desc = string("F¸hren Sie bitte eine OpenVAS-Pr¸fung Ihres Netzwerkes mit\ndem aktuellen NVT-Set aus.");
  }
  else {
    result = string("nicht zutreffend");
    desc = string("Das System ist kein Windows Terminal Server. (Zur Zeit kann\nnur auf Windows Terminal Server getestet werden.)");
  }
}

set_kb_item(name:"GSHB-12/M4_368/result", value:result);
set_kb_item(name:"GSHB-12/M4_368/desc", value:desc);
set_kb_item(name:"GSHB-12/M4_368/name", value:name);

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
