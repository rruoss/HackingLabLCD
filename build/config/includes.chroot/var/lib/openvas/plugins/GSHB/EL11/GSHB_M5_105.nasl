###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M5_105.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 11. EL, Maﬂnahme 5.105
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
tag_summary = "IT-Grundschutz M5.105: Vorbeugen vor SYN-Attacken auf den IIS (Win).

  Diese Pr¸fung bezieht sich auf die 11. Erg‰nzungslieferung (11. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
  Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

  http://www.bsi.bund.de/grundschutz/kataloge/m/m05/m05105.html";


if(description)
{
  script_id(895105);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Thu Jan 14 14:29:35 2010 +0100");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M5.105: Vorbeugen vor SYN-Attacken auf den IIS (Win)");
  if (! OPENVAS_VERSION)
  {
    desc = "
    Leider setzen Sie einen zu alten OpenVAS Scan-Server ein.
    Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!";
    script_description(desc);
    script_summary("IT-Grundschutz M5.105: Vorbeugen vor SYN-Attacken auf den IIS (Win).");
    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
    script_family("IT-Grundschutz-11");
    exit(0);
  }
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("IT-Grundschutz M5.105: Vorbeugen vor SYN-Attacken auf den IIS (Win).");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-11");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-11");
  script_dependencies("GSHB/GSHB_WMI_IIS_Protect_SynAttack.nasl", "GSHB/GSHB_WMI_IIS_OpenPorts.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  script_require_keys("WMI/IISandPorts","WMI/IISSynAttack");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M5.105: Vorbeugen vor SYN-Attacken auf den IIS (Win)\n';

if (! OPENVAS_VERSION)
{
        set_kb_item(name:"GSHB-11/M5_105/result", value:"nicht zutreffend");
        set_kb_item(name:"GSHB-11/M5_105/desc", value:"Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!");
        set_kb_item(name:"GSHB-11/M5_105/name", value:name);
    log_message(port:0, proto: "IT-Grundschutz", data:string("Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!"));  
    exit(0);
}


gshbm =  "IT-Grundschutz M5.105: ";
WMIOSLOG = get_kb_item("WMI/WMI_OS/log");
IISVER = get_kb_item("WMI/IISandPorts");
SynAttack = get_kb_item("WMI/IISSynAttack");
TCPMaxCon = get_kb_item("WMI/TcpMaxConnectResponseRetransmissions");
Backlog = get_kb_item("WMI/BacklogIncrement");
MaxCon = get_kb_item("WMI/MaxConnBackLog");
EnDyn = get_kb_item("WMI/EnableDynamicBacklog");
MinDyn = get_kb_item("WMI/MinimumDynamicBacklog");
MaxDyn = get_kb_item("WMI/MaximumDynamicBacklog");
DynDelta = get_kb_item("WMI/DynamicBacklogGrowthDelta");
log = get_kb_item("WMI/IISandPorts/log");


if (WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System."){
  result = string("nicht zutreffend");
  desc = string("Auf dem System l‰uft Samba, es ist kein Microsoft System.");
}else if("error" >< IISVER){
  result = string("Fehler");
  if (!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
  if (log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
}else if("None" >< IISVER || "None" >< SynAttack){
  result = string("nicht zutreffend");
  desc = string("Auf dem System ist kein IIS installiert.");
}else if(("None" >!< TCPMaxCon && TCPMaxCon <= 2) && ("None" >!< Backlog) && ("None" >!< MaxCon) && ("None" >!< EnDyn && EnDyn == "1") && ("None" >!< MinDyn && MinDyn == "14") && ("None" >!< MaxDyn) && ("None" >!< DynDelta && DynDelta == "A")){
  result = string("erf¸llt");
  desc = string("Das System entspricht der Maﬂnahme 5.105.");
}else if(("None" >< TCPMaxCon || TCPMaxCon > 2) || ("None" >< Backlog) || ("None" >< MaxCon) || ("None" >< EnDyn || EnDyn != "1") || ("None" >< MinDyn || MinDyn != "14") || ("None" >< MaxDyn) || ("None" >< DynDelta || DynDelta != "A")){
  result = string("nicht erf¸llt");
  if ("None" >< TCPMaxCon || TCPMaxCon > 2) desc = string('TcpMaxConnectResponse-Retransmissions wurde nicht korrekt\nkonfiguriert.\n');
  if ("None" >< Backlog) desc = desc + string('Einstellen der zunehmenden Verbindungsblˆcke\n(INCREASING CONNECTION BLOCK INCREMENT) wurde nicht korrekt\nkonfiguriert.\n');
  if ("None" >< MaxCon) desc = desc + string('Einstellen der maximalen Verbindungsblˆcke\n(MAXIMUM CONNECTION BLOCKS) wurde nicht korrekt konfiguriert.\n');
  if ("None" >< EnDyn || EnDyn != "1") desc = desc + string('Einstellen des dynamischen Reserve-Verhaltens\n(EnableDynamicBacklog) wurde nicht korrekt konfiguriert.\n');
  if ("None" >< MinDyn || MinDyn != "14") desc = desc + string('Einstellen des dynamischen Reserve-Verhaltens\n(MinimumDynamicBacklog) wurde nicht korrekt konfiguriert.\n');
  if ("None" >< MaxDyn) desc = desc + string('Einstellen des dynamischen Reserve-Verhaltens\n(MaximumDynamicBacklog) wurde nicht korrekt konfiguriert.\n');
  if ("None" >< DynDelta || DynDelta != "A") desc = desc + string('Einstellen des dynamischen Reserve-Verhaltens\n(DynamicBacklogGrowthDelta) wurde nicht korrekt konfiguriert.\n');
}



set_kb_item(name:"GSHB-11/M5_105/result", value:result);
set_kb_item(name:"GSHB-11/M5_105/desc", value:desc);
set_kb_item(name:"GSHB-11/M5_105/name", value:name);

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
