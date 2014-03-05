###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M5_091.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 11. EL, Ma�nahme 5.091
#
# Authors:
# Thomas Rotter <T.Rotter@dn-systems.de>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "IT-Grundschutz M5.091: Einsatz von Personal Firewalls f�r Internet-PCs.

  Diese Pr�fung bezieht sich auf die 11. Erg�nzungslieferung (11. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Ma�nahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Erg�nzungslieferung bezieht. Titel und Inhalt k�nnen sich bei einer
  Aktualisierung �ndern, allerdings nicht die Kernthematik.

  Hinweis:
  
  Getestet wird auf die Microsoft Windows Firewall. F�r Vista und Windows 7 
  auf jegliche Firewall die sich systemkonform installiert. 
  Auf Linux, soweit m�glich, anzeige der iptables Regeln.

  http://www.bsi.bund.de/grundschutz/kataloge/m/m05/m05091.html";


if(description)
{
  script_id(895091);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Tue Jan 26 13:42:28 2010 +0100");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M5.091: Einsatz von Personal Firewalls f�r Internet-PCs");
  if (! OPENVAS_VERSION)
  {
    desc = "
    Leider setzen Sie einen zu alten OpenVAS Scan-Server ein.
    Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!";
    script_description(desc);
    script_summary("IT-Grundschutz M5.091: Einsatz von Personal Firewalls f�r Internet-PCs.");
    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
    script_family("IT-Grundschutz-11");
    exit(0);
  }
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("IT-Grundschutz M5.091: Einsatz von Personal Firewalls f�r Internet-PCs.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-11");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-11");
  script_dependencies("GSHB/GSHB_WMI_OSInfo.nasl", "GSHB/GSHB_WMI_WinFirewallStat.nasl", "GSHB/GSHB_SSH_iptables.nasl");
#  script_require_keys("WMI/WinFirewall");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M5.091: Einsatz von Personal Firewalls f�r Internet-PCs\n';

if (! OPENVAS_VERSION)
{
        set_kb_item(name:"GSHB-11/M5_091/result", value:"nicht zutreffend");
        set_kb_item(name:"GSHB-11/M5_091/desc", value:"Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!");
        set_kb_item(name:"GSHB-11/M5_091/name", value:name);
    log_message(port:0, proto: "IT-Grundschutz", data:string("Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!"));  
    exit(0);
}



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


ruleset = get_kb_item("GSHB/iptables/ruleset");
targets = get_kb_item("GSHB/iptables/targets");
names = get_kb_item("GSHB/iptables/names");
matches = get_kb_item("GSHB/iptables/matches");
iptableslog = get_kb_item("GSHB/iptables/log");
uname = get_kb_item("GSHB/iptables/uname");
sunipfilter = get_kb_item("GSHB/iptables/ipfilter");
sunipfilterstat = get_kb_item("GSHB/iptables/ipfilterstat");  

gshbm = "GSHB Ma�nahme 5.091: ";


if (OSVER != "none"){
  if(FW == "error"){
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
      desc = string("Auf dem System ist folgende Firewall Software aktiviert:\n" + Firewall_Name);
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
      desc = string("\nAuf dem System ist die Windows Firewall nur f�r\n-�ffentliche Netzwerke- aktiviert. Sie sollten die Windows\nFirewall f�r s�mtliche Netzwerke aktivieren.");
    }else if (STD == "1" && PUB == "off"){
      result = string("unvollst�ndig");
      desc = string("\nAuf dem System ist die Windows Firewall nur f�r\n-Private- / Arbeitsplatz Netzwerke- aktiviert. Sie sollten die\nWindows Firewall f�r s�mtliche Netzwerke aktivieren.");
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
}else{
  if(ruleset == "windows") {
    result = string("Fehler");
    if (OSNAME >!< "none" && OSNAME >!< "error") desc = string('\nFolgendes System wurde erkannt:\n' + OSNAME + '\nAllerdings konnte auf das System nicht korrekt zugegriffen\nwerden. Folgende Fehler sind aufgetreten:\n' + log);
    else desc = string('\nDas System scheint ein Windows-System zu sein. Allerdings\nkonnte auf das System nicht korrekt zugegriffen werden.\nFolgende Fehler sind aufgetreten:\n' + log);
  }else if(uname =~ "SunOS.*"){
    if(sunipfilter == "noperm" || sunipfilterstat =="noperm"){
      result = string("Fehler");
      desc = string("Beim Testen des Systems trat ein Fehler auf.");
      if(sunipfilter == "noperm")desc += string('\nSie haben nicht die Berechtigung um den Befehl\n"ipf -V" auszuf�hren.');
      if(sunipfilterstat =="noperm")desc += string('\nSie haben nicht die Berechtigung um den Befehl\n"ipfstat -io" auszuf�hren.');
    }else if(sunipfilter == "notfound" || sunipfilterstat =="notfound"){
      result = string("Fehler");
      desc = string("Beim Testen des Systems trat ein Fehler auf.");
      if(sunipfilter == "notfound")desc += string('\nDer Befehl "ipf -V" konnte nicht gefunden, bzw ausgef�hrt\nwerden.');
      if(sunipfilterstat =="notfound")desc += string('\nDer Befehl "ipfstat -io" konnte nicht gefunden, bzw ausgef�hrt\nwerden.');
    }else if(sunipfilter == "off"){
      result = string("nicht erf�llt");
      desc = string('Eine Abfrage mit ipf -V hat ergeben, dass keine IP Filter\nlaufen.');
    }else if (sunipfilter == "on"){
      if (sunipfilterstat == "nofilter"){
        result = string("nicht erf�llt");
        desc = string('Beim Aufruf des Befehls ipfstat -io wurden keine IP Filter\nzur�ckgegeben.');
      }else{
        result = string("unvollst�ndig");
        desc = string('Bitte �berpr�fen Sie das iptables ruleset:\n' + ipfilterstat);  
      }
    }else if(sunipfilter != "off" && sunipfilter != "on"){
      result = string("Fehler");
      if (!iptableslog) desc = string("Beim Testen des Systems trat ein Fehler auf.");
      if (iptableslog) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
    }
  }else if(ruleset == "error"){
    result = string("Fehler");
    if (!iptableslog) desc = string("Beim Testen des Systems trat ein Fehler auf.");
    if (iptableslog) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
  }else if ((ruleset == "notfound" || ruleset == "noperm") && (("notfound" >!< targets && "none" >!< targets) && ("notfound" >!< names && "none" >!< names) && ("notfound" >!< matches && "none" >!< matches))){
    result = string("unvollst�ndig");
    if (ruleset == "notfound") desc = string("Der Befehl iptables konnte nicht gefunden werden.\nWahrscheinlich reicht die Berechtigung nicht aus.");
    else if (ruleset == "noperm") desc = string("Der Befehl iptables konnte nicht ausgef�hrt werden, da die\nBerechtigung nicht ausreicht.");
    desc += string('\nFolgende iptables Module wurden im proc Filesystem gefunden:\n'+ targets + names + matches + '\nBitte �berpr�fen Sie die iptable rules manuell.');
  }else if (ruleset == "notfound" || ruleset == "noperm" && (("notfound" == targets || "none" == targets) && ("notfound" == names || "none" == names) && ("notfound" == matches || "none" == matches))){
    result = string("nicht erf�llt");
    desc = string('Es war nicht m�glich den Befehl iptabels auszuf�hren und es\nwurden keine iptables Module im proc Filesystem gefunden.');
  }else{
    result = string("unvollst�ndig");
    desc = string('Bitte �berpr�fen Sie das iptables ruleset:\n' + ruleset);  
  }
}

if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler auf\nbzw. es konnte kein Ergebnis ermittelt werden.'); 
}

set_kb_item(name:"GSHB-11/M5_091/result", value:result);
set_kb_item(name:"GSHB-11/M5_091/desc", value:desc);
set_kb_item(name:"GSHB-11/M5_091/name", value:name);

silence = get_kb_item("GSHB-11/silence");

if (silence){
exit(0);
} else {
  report = 'Ergebnisse zum IT-Grundschutz, 11. Erg�nzungslieferung:\n\n';
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
