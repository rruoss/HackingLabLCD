###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_049.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 10. EL, Maﬂnahme 4.049
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
tag_summary = "IT-Grundschutz M4.049: Absicherung des Boot-Vorgangs f¸r ein Windows NT/2000/XP System (Win).

  Diese Pr¸fung bezieht sich auf die 10. Erg‰nzungslieferung (10. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
  Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

  http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04049.html";


if(description)
{
  script_id(94049);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Thu Jan 14 14:29:35 2010 +0100");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.049: Absicherung des Boot-Vorgangs f¸r ein Windows NT/2000/XP System (Win)");
  if (! OPENVAS_VERSION)
  {
    desc = "
    Leider setzen Sie einen zu alten OpenVAS Scan-Server ein.
    Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!";
    script_description(desc);
    script_summary("IT-Grundschutz M4.049: Absicherung des Boot-Vorgangs f¸r ein Windows NT/2000/XP System (Win).");
    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
    script_family("IT-Grundschutz-10");
    exit(0);
  }
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("IT-Grundschutz M4.049: Absicherung des Boot-Vorgangs f¸r ein Windows NT/2000/XP System (Win).");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-10");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-10");
  script_dependencies("GSHB/GSHB_WMI_BootDrive.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  script_require_keys("WMI/FS", "WMI/FDD", "WMI/CD", "WMI/USB", "WMI/BOOTINI" );
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.049: Absicherung des Boot-Vorgangs f¸r ein Windows NT/2000/XP System (Win)\n';

if (! OPENVAS_VERSION)
{
        set_kb_item(name:"GSHB-10/M4_049/result", value:"nicht zutreffend");
        set_kb_item(name:"GSHB-10/M4_049/desc", value:"Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!");
        set_kb_item(name:"GSHB-10/M4_049/name", value:name);
    log_message(port:0, proto: "IT-Grundschutz", data:string("Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!"));  
    exit(0);
}


gshbm =  "IT-Grundschutz M4.049: ";

FS= get_kb_item("WMI/FS");
FDD = get_kb_item("WMI/FDD");
CD = get_kb_item("WMI/CD");
USB = get_kb_item("WMI/USB");
BOOTINI = get_kb_item("WMI/BOOTINI");
log = get_kb_item("WMI/BOOTDRIVE/log");
WMIOSLOG = get_kb_item("WMI/WMI_OS/log");


if (WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System."){
  result = string("nicht zutreffend");
  desc = string("Auf dem System l‰uft Samba, es ist kein Microsoft System.");
}else if("error" >< FS || "error" >< FDD || "error" >< CD || "error" >< USB || "error" >< BOOTINI){
  result = string("Fehler");
  if (!log)desc = string("Beim Testen des Systems trat ein Fehler auf, siehe Log Message!");
  if (log)desc = string("Beim Testen des Systems trat ein Fehler auf: " + log);
}else if("None" >< FS && "None" >< FDD && "None" >< CD && "None" >< USB || "none" >< BOOTINI){
  result = string("Fehler");
  desc = string("Beim Testen des Systems trat ein Fehler auf, siehe Log Message!");
}else if("True" >< BOOTINI || "None" >!< FDD || "None" >!< CD || "None" >!< USB || "FAT" >< FS){
  result = string("nicht erf¸llt");
  if("True" >< BOOTINI) desc =string("Boot.ini ist beschreibbar, bitte achten Sie darauf, das die Boot.ini schreibgesch¸tzt ist und entsprechende NTFS Berechtigungen gesetzt sind." + '\n');
  if("None" >!< FDD)desc = desc + string("Sie sollten aus Sicherheitsgr¸nden das Diskettenlaufwerk entfernen oder zumindest sperren." + '\n');
  if("None" >!< CD)desc = desc + string("Sie sollten aus Sicherheitsgr¸nden das CD-ROM Laufwerk entfernen oder zumindest sperren." + '\n');
  if("None" >!< USB)desc = desc + string("Sie sollten aus Sicherheitsgr¸nden den USB Controller entfernen oder zumindest im BIOS deaktivieren." + '\n');
  if("FAT" >< FS){
    LD = split(FS, sep:'\n', keep:0);
    for(i=1; i<max_index(LD); i++)
      {
        LDinf = split(LD[i], sep:"|", keep:0);
        if(LDinf !=NULL)
        {
          if("FAT" >< LDinf[1]) LDdesc = LDdesc + "Laufwerksbuchstabe: " + LDinf[0] + ', Dateisystem: ' + LDinf[1] + ', ';
         }
      }
    desc = desc + string("Folgende Logischen Laufwerke sind nicht NFTS Formatiert: " + '\n' + LDdesc + '\n');
  }
}else if("FAT" >!< FS && "None" >< FDD && "None" >< CD && "None" >< USB && "False" >< BOOTINI){
  result = string("erf¸llt");
  desc = string("Ihr System entspricht der Maﬂnahme M4.049");
}

set_kb_item(name:"GSHB-10/M4_049/result", value:result);
set_kb_item(name:"GSHB-10/M4_049/desc", value:desc);
set_kb_item(name:"GSHB-10/M4_049/name", value:name);

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
