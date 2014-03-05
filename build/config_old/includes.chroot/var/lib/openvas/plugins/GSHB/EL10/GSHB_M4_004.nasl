###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_004.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 10. EL, Maﬂnahme 4.004
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
tag_summary = "IT-Grundschutz M4.004: Geeigneter Umgang mit Laufwerken f¸r Wechselmedien und externen Datenspeicher.

  Diese Pr¸fung bezieht sich auf die 10. Erg‰nzungslieferung (10. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
  Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

  http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04004.html";


if(description)
{
  script_id(94004);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Thu Jan 14 14:29:35 2010 +0100");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.004: Geeigneter Umgang mit Laufwerken f¸r Wechselmedien und externen Datenspeichern");
  if (! OPENVAS_VERSION)
  {
    desc = "
    Leider setzen Sie einen zu alten OpenVAS Scan-Server ein.
    Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!";
    script_description(desc);
    script_summary("IT-Grundschutz M4.004: Geeigneter Umgang mit Laufwerken f¸r Wechselmedien und externen Datenspeicher.");
    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
    script_family("IT-Grundschutz-10");
    exit(0);
  }
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("IT-Grundschutz M4.004: Geeigneter Umgang mit Laufwerken f¸r Wechselmedien und externen Datenspeicher.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-10");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-10");
  script_dependencies("GSHB/GSHB_WMI_OSInfo.nasl", "GSHB/GSHB_WMI_removable-media.nasl", "GSHB/GSHB_SSH_USB_storage.nasl");
  script_require_keys("WMI/CD_driver_start", "WMI/FD_driver_start", "WMI/SF_driver_start", "WMI/USB_driver_start", "WMI/StorageDevicePolicies");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.004: Geeigneter Umgang mit Laufwerken f¸r Wechselmedien und externen Datenspeichern\n';

if (!OPENVAS_VERSION)
{
        set_kb_item(name:"GSHB-10/M4_004/result", value:"nicht zutreffend");
        set_kb_item(name:"GSHB-10/M4_004/desc", value:"Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!");
        set_kb_item(name:"GSHB-10/M4_004/name", value:name);
    log_message(port:0, proto: "IT-Grundschutz", data:string("Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!"));  
    exit(0);
}


OSNAME = get_kb_item("WMI/WMI_OSNAME");

cdstart = get_kb_item("WMI/CD_driver_start"); 
fdstart = get_kb_item("WMI/FD_driver_start");
sfstart = get_kb_item("WMI/SF_driver_start");
usbstart = get_kb_item("WMI/USB_driver_start");
sdp = get_kb_item("WMI/StorageDevicePolicies");
log = get_kb_item("WMI/StorageDevicePolicies/log");

usbmodules = get_kb_item("GSHB/usbmodules");
usbstorage = get_kb_item("GSHB/usbstorage");
usbbus = get_kb_item("GSHB/usbbus");
sshlog = get_kb_item("GSHB/usbmodules/log");
    

gshbm =  "IT-Grundschutz M4.004: ";

if (OSNAME >!< "none"){

  if(cdstart >< "error" && fdstart >< "error" && sfstart >< "error" && usbstart >< "error" && sdp >< "error"){
    result = string("Fehler");
    if (!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
    if (log) desc = string("Beim Testen des Systems trat ein Fehler auf: " + log);
  } else if(cdstart >< "inapplicable" && fdstart >< "inapplicable" && sfstart >< "inapplicable" && usbstart >< "inapplicable" && sdp >< "inapplicable"){
    result = string("nicht zutreffend");
    desc = string("Das System wurde nicht getestet, da es anscheinend kein Windows-System ist.");
  } else if(cdstart >< "off" && fdstart >< "off" && sfstart >< "off" && usbstart >< "off"){
    result = string("erf¸llt");
    desc = string("Dienste f¸r Wechseldatentr‰ger sind deaktiviert.");
  } else if(cdstart >< "off" && fdstart >< "off" && sfstart >< "off" && usbstart >< "inapplicable"){
    result = string("erf¸llt");
    desc = string("Dienste f¸r Wechseldatentr‰ger sind deaktiviert. Allerdings wurde noch kein USB-Ger‰t angeschlossen, so dass dort kein Test durchgef¸hrt werden konnte.");
  } else if((cdstart >< "on" || fdstart >< "on" || sfstart >< "on" || usbstart >< "on") && sdp >< "on"){
    result = string("nicht erf¸llt");
    desc = string("Dienste f¸r Wechseldatentr‰ger sind nicht deaktiviert. Allerdings wurden sie auf 'nur lesen' gesetzt.");
  } else {
    result = string("nicht erf¸llt");
    desc = string("Dienste f¸r Wechseldatentr‰ger sind nicht deaktiviert.");
  }
}else{
  if(usbmodules >< "error" && usbstorage >< "error" && usbbus >< "error"){
    result = string("Fehler");
    if (!sshlog) desc = string("Beim Testen des Systems trat ein Fehler auf.");
    if (sshlog) desc = string("Beim Testen des Systems trat ein Fehler auf: " + sshlog);
  } else if (usbmodules >< "none" && usbstorage >< "none" && usbbus >< "none"){
    result = string("erf¸llt");
    desc = string("Es konnte kein angeschlossenes USB-Storage Ger‰t gefunden werden.\nDes weiteren wurde keine USB-Storage Kernelmodule gefunden.");  
  } else{
    result = string("nicht erf¸llt");
    if (usbstorage != "none") desc = string('Es wurden folgende angeschlossenen USB-Storage Ger‰t gefunden:\n' + usbstorage);
    if (usbmodules != "none") desc += string('\nEs wurden folgende USB-Storage Kernelmodule gefunden:\n' + usbmodules);
    if (usbbus != "none") desc += string('\nAufgrund der vorgefundenen Verzeichnisstrucktur -/sys/bus/usb/drivers/usb-storage- muss davon ausgegangen werden, dass USB-Storage Kernelmodule vorhanden sind:\n' + usbbus);    
  }
}

if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler auf bzw. es konnte kein Ergebnis ermittelt werden.'); 
}

set_kb_item(name:"GSHB-10/M4_004/result", value:result);
set_kb_item(name:"GSHB-10/M4_004/desc", value:desc);
set_kb_item(name:"GSHB-10/M4_004/name", value:name);

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


