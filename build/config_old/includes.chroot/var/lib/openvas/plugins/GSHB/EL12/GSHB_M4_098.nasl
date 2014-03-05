###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_098.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 12. EL, Ma�nahme 4.098
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
tag_summary = "IT-Grundschutz M4.098: Kommunikation durch Paketfilter auf Minimum beschr�nken (Win).

Diese Pr�fung bezieht sich auf die 12. Erg�nzungslieferung (12. EL) des IT-
Grundschutz. Die detaillierte Beschreibung zu dieser Ma�nahme findet sich unter
nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
die aktuellste Erg�nzungslieferung bezieht. Titel und Inhalt k�nnen sich bei einer
Aktualisierung �ndern, allerdings nicht die Kernthematik.

Hinweis:

Getestet wird auf die Microsoft Windows Firewall. F�r Vista und Windows 7 
auf jegliche Firewall die sich systemkonform installiert.

http://www.bsi.bund.de/grundschutz/kataloge/m/m05/m04098.html";


if(description)
{
  script_id(94060);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2011-11-07 13:38:53 +0100 (Mon, 07 Nov 2011)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.098: Kommunikation durch Paketfilter auf Minimum beschr�nken (Win)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("IT-Grundschutz M4.098: Kommunikation durch Paketfilter auf Minimum beschr�nken (Win).");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-12");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-12");
  script_dependencies("GSHB/GSHB_WMI_OSInfo.nasl", "GSHB/GSHB_WMI_WinFirewallStat.nasl");
  script_require_keys("WMI/WinFirewall");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.098: Kommunikation durch Paketfilter auf Minimum beschr�nken (Win)\n';

OSVER = get_kb_item("WMI/WMI_OSVER");
OSTYPE = get_kb_item("WMI/WMI_OSTYPE");
Domainrole = get_kb_item("WMI/WMI_WindowsDomainrole");
SMBOSVER = get_kb_item("SMB/WindowsVersion");
WMIOSLOG = get_kb_item("WMI/WMI_OS/log");
FW = get_kb_item("WMI/WinFirewall");
IPFilter = get_kb_item("WMI/WinFirewall/IPFilter");
STD = get_kb_item("WMI/WinFirewall/STD");
DOM = get_kb_item("WMI/WinFirewall/DOM");
PUB = get_kb_item("WMI/WinFirewall/PUB");
Firewall_Name = get_kb_item("WMI/WinFirewall/Firewall_Name");
Firewall_State = get_kb_item("WMI/WinFirewall/Firewall_State");
log = get_kb_item("WMI/WinFirewall/log");
  
gshbm = "GSHB Ma�nahme 4.098: ";


if (WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System."){
  result = string("nicht zutreffend");
  desc = string("Auf dem System l�uft Samba,\nes ist kein Microsoft Windows System.");
}else if(FW == "error"){
  result = string("Fehler");
  if (!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
  if (log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
}else if (OSVER < '5.1'){
  result = string("unvollst�ndig");
  desc = string("Das Windows 2000 System kann nicht gepr�ft werden.");
}else if (FW == "on"){
  result = string("erf�llt");
  desc = string("Auf dem System ist eine Personal Firewall aktiviert.");
}else if(OSVER == "5.2" && OSTYPE != "none" && OSTYPE > 1){

  IPFilter = split(IPFilter, sep:'\n', keep:0);
  IPFilter = split(IPFilter[1], sep:'|', keep:0);
  NWCard = IPFilter[0];
  IPFilter = IPFilter[2];

  if (IPFilter == "True"){
    result = string("erf�llt");
    desc = string("Auf dem System ist die Windows Firewall f�r folgende\nNetzwerkkarte aktiviert:\n" + NWCard);
    }else{
    result = string("nicht erf�llt");
    desc = string("Auf dem System ist keine Personal Firewall aktiviert.");
    }
}else if(Firewall_State != "none" && Firewall_State != "inapplicable"){

  Firewall_Name = split(Firewall_Name, sep:'\n', keep:0);
  Firewall_Name = split(Firewall_Name[1], sep:'|', keep:0);
  Firewall_Name = Firewall_Name[0];  

  Firewall_State = split(Firewall_State, sep:'\n', keep:0);
  Firewall_State = split(Firewall_State[1], sep:'|', keep:0);
  Firewall_State = Firewall_State[1];
  
  if(Firewall_State == "266256"){
    result = string("erf�llt");
    desc = string("Auf dem System ist folgende Firewall Software\naktiviert: " + Firewall_Name);
  }else if(Firewall_State == "262160" && Domainrole == "0" && STD =="1"){
    result = string("erf�llt");
    desc = string("Auf dem System ist die Windows Firewall aktiviert.");
  }else if(Firewall_State == "262160" && Domainrole == "0" && STD =="off"){
    result = string("nicht erf�llt");
    desc = string("Auf dem System ist keine Personal Firewall aktiviert.");
  }else if(Firewall_State == "262160" && Domainrole == "1" && DOM =="1"){
    result = string("erf�llt");
    desc = string("Auf dem System ist die Windows Firewall aktiviert.");
  }else if(Firewall_State == "262160" && Domainrole == "1" && DOM =="off"){
    result = string("nicht erf�llt");
    desc = string("Auf dem System ist keine Personal Firewall aktiviert.");
  } 
}else if(Domainrole == "0" || Domainrole == "2"){
  if (STD == "off" && PUB == "off"){
    result = string("nicht erf�llt");
    desc = string("Auf dem System ist keine Personal Firewall aktiviert.");
  }else if (STD == "1" && PUB == "1"){
    result = string("erf�llt");
    desc = string("Auf dem System ist die Windows Firewall aktiviert.");  
  }else if (STD == "off" && PUB == "1"){
    result = string("unvollst�ndig");
    desc = string("Auf dem System ist die Windows Firewall nur f�r\n-�ffentliche Netzwerke- aktiviert. Sie sollten die\nWindows Firewall f�r s�mtliche Netzwerke aktivieren.");
  }else if (STD == "1" && PUB == "off"){
    result = string("unvollst�ndig");
    desc = string("Auf dem System ist die Windows Firewall nur f�r\n-Private- / Arbeitsplatz Netzwerke- aktiviert. Sie\nsollten die Windows Firewall f�r s�mtliche Netzwerke\naktivieren.");
  }
}else if(Domainrole == "1" || Domainrole > 2 ){
  if (DOM == "off"){
    result = string("nicht erf�llt");
    desc = string("Auf dem System ist keine Personal Firewall aktiviert.");
  }else if (DOM == "1"){
    result = string("erf�llt");
    desc = string("Auf dem System ist die Windows Firewall aktiviert.");  
  }
}

set_kb_item(name:"GSHB-12/M4_098/result", value:result);
set_kb_item(name:"GSHB-12/M4_098/desc", value:desc);
set_kb_item(name:"GSHB-12/M4_098/name", value:name);

silence = get_kb_item("GSHB-12/silence");

if (silence){
exit(0);
} else {
  report = 'Ergebnisse zum IT-Grundschutz, 12. Erg�nzungslieferung:\n\n';
  report = report + name + 'Ergebnis:\t' + result +
           '\nDetails:\t' + desc + '\n\n';
    if ("nicht erf�llt" >< result || result >< "Fehler"){
    security_hole(port:0, proto: "IT-Grundschutz", data:report);
    } else if (result >< "unvollst�ndig"){
    security_warning(port:0, proto: "IT-Grundschutz", data:report);
    } else if (result >< "erf�llt" || result >< "nicht zutreffend"){
    security_note(port:0, proto: "IT-Grundschutz", data:report);
    }
exit(0);
}
