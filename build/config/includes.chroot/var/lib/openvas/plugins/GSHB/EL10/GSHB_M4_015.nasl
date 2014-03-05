##############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_015.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 10. EL, Maﬂnahme 4.015
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
tag_summary = "IT-Grundschutz M4.015: Gesichertes Login

  Diese Pr¸fung bezieht sich auf die 10. Erg‰nzungslieferung (10. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
  Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

  http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04015.html";


if(description)
{
  script_id(94015);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Fri May 21 15:05:08 2010 +0200");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.015: Gesichertes Login");
  if (! OPENVAS_VERSION)
  {
    desc = "
    Leider setzen Sie einen zu alten OpenVAS Scan-Server ein.
    Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!";
    script_description(desc);
    script_summary("IT-Grundschutz M4.015: Gesichertes Login");
    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
    script_family("IT-Grundschutz-10");
    exit(0);
  }
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("IT-Grundschutz M4.015: Gesichertes Login");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-10");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-10");
  script_dependencies("GSHB/GSHB_WMI_OSInfo.nasl", "GSHB/GSHB_SSH_PAM.nasl", "GSHB/GSHB_WMI_PolSecSet.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.015: Gesichertes Login\n';

if (! OPENVAS_VERSION)
{
        set_kb_item(name:"GSHB-10/M4_015/result", value:"nicht zutreffend");
        set_kb_item(name:"GSHB-10/M4_015/desc", value:"Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!");
        set_kb_item(name:"GSHB-10/M4_015/name", value:name);
    log_message(port:0, proto: "IT-Grundschutz", data:string("Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!"));  
    exit(0);
}

OSNAME = get_kb_item("WMI/WMI_OSNAME");
OSVER = get_kb_item("WMI/WMI_OSVER");
WindowsDomainrole = get_kb_item("WMI/WMI_WindowsDomainrole");
DisplayLastLogonInfo = get_kb_item("WMI/cps/DisplayLastLogonInfo");
LDAPDomFunkMod = get_kb_item("GSHB/LDAP/DomFunkMod");
DomFunkMod = get_kb_item("GSHB/DomFunkMod");
if ((!DomFunkMod || DomFunkMod >< "none") && LDAPDomFunkMod) DomFunkMod = LDAPDomFunkMod;
else if (LDAPDomFunkMod && int(LDAPDomFunkMod) > 2 && int(LDAPDomFunkMod) > int(DomFunkMod))DomFunkMod = LDAPDomFunkMod;

if (DomFunkMod == 0)level = "Windows 2000 gemischt und Windows 2000 pur";
else if (DomFunkMod == 1)level = "Windows Server 2003 Interim";
else if (DomFunkMod == 2)level = "Windows Server 2003";
else if (DomFunkMod == 3)level = "Windows Server 2008";
else if (DomFunkMod == 4)level = "Windows Server 2008 R2";

uname = get_kb_item("GSHB/PAM/uname");
solpamconf = get_kb_item("GSHB/PAM/CONF");

pamlogin = get_kb_item("GSHB/PAM/login");
login_pamlastlog = get_kb_item("GSHB/PAM/login/lastlog");
login_pamlimits = get_kb_item("GSHB/PAM/login/limits");
login_pamtally = get_kb_item("GSHB/PAM/login/tally");

pamsshd = get_kb_item("GSHB/PAM/sshd");
sshd_pamlastlog = get_kb_item("GSHB/PAM/sshd/lastlog");
sshd_pamlimits = get_kb_item("GSHB/PAM/sshd/limits");
sshd_pamtally = get_kb_item("GSHB/PAM/sshd/tally");

pamgdm = get_kb_item("GSHB/PAM/gdm");
gdm_pamlastlog = get_kb_item("GSHB/PAM/gdm/lastlog");
gdm_pamlimits = get_kb_item("GSHB/PAM/gdm/limits");
gdm_pamtally = get_kb_item("GSHB/PAM/gdm/tally");

pamxdm = get_kb_item("GSHB/PAM/xdm");
xdm_pamlastlog = get_kb_item("GSHB/PAM/xdm/lastlog");
xdm_pamlimits = get_kb_item("GSHB/PAM/xdm/limits");
xdm_pamtally = get_kb_item("GSHB/PAM/xdm/tally");

pamkde = get_kb_item("GSHB/PAM/kde");
kde_pamlastlog = get_kb_item("GSHB/PAM/kde/lastlog");
kde_pamlimits = get_kb_item("GSHB/PAM/kde/limits");
kde_pamtally = get_kb_item("GSHB/PAM/kde/tally");

limits = get_kb_item("GSHB/PAM/limits");

log = get_kb_item("GSHB/PAM/log");

if(OSNAME >!< "none"){
  if (WindowsDomainrole == "0" || WindowsDomainrole == "2"){
    result = string("nicht zutreffend");
    desc = string('Das System ist kein Mitglied in einer Windows Domain. Der Test kann nur auf Windows Domain Mitglieder ausgef¸hrt werden.');
  }else if(DomFunkMod >< "none" && !LDAPDomFunkMod){
    result = string("Fehler");
    desc = string('Bitte konfigurieren Sie den DomainFunktionslevel in den Einstellungen (Network Vulnerability Test Preferences) unter Compliance Tests/Windows Domaenenfunktionsmodus!');
  }else if(int(OSVER) < 6){
    result = string("nicht zutreffend");
    desc = string('Das System ist ein "' + OSNAME + '" System. Die notwendige Konfiguration ist erst ab Windows Vista mˆglich.');
  }else if(int(DomFunkMod) < 3){
    result = string("nicht zutreffend");
    desc = string('Das System ist Mitglied in einer Windows Domain die im Funtionslevel "' + level + '" l‰uft. Die notwendige Konfiguration ist erst ab dem Funktionslevel "Windows Server 2008" mˆglich.');
  }else {
    if (!DisplayLastLogonInfo){
      result = string("nicht erf¸llt");
      desc = string('"Informationen zu vorherigen Anmeldungen bei der Benutzeranmeldung anzeigen" wurde in keiner Gruppenrichtlinie gesetzt.');
    }else if(DisplayLastLogonInfo == "1"){
      result = string("erf¸llt");
      desc = string('"Informationen zu vorherigen Anmeldungen bei der Benutzeranmeldung anzeigen" wurde innerhalb einer Gruppenrichtlinie gesetzt.');
    }
  }
}else if(pamlogin == "windows") {
    result = string("nicht zutreffend");
    desc = string('Das System scheint ein Windows-System zu sein wurde aber nicht richtig erkannt.');
}else if (uname =~ "SunOS .*"){
  if (solpamconf >< "none"){
    result = string("Fehler");
    desc = string('Beim Testen des Systems trat ein Fehler auf: /etc/pam.conf konnte nicht gelesen werden.'); 
  }else if (solpamconf >< "read"){
    result = string("unvollst‰ndig");
    desc = string('Das System ist ein ' + uname + ' System. Zur Zeit kˆnnen diese Systeme noch nicht getestet werden.'); 
  }
}else if(pamlogin >< "error"){
  result = string("Fehler");
  if (!log)desc = string('Beim Testen des Systems trat ein unbekannter Fehler auf, siehe Log Message!');
  if (log)desc = string('Beim Testen des Systems trat ein Fehler auf:\n' + log);
}else if(pamlogin == "none" && pamsshd == "none" && pamgdm == "none" && pamxdm == "none" && pamkde == "none"){
  result = string("Fehler");
  desc = string('Die Dateien /etc/pam.d/login, /etc/pam.d/sshd, /etc/pam.d/gdm, /etc/pam.d/xdm und /etc/pam.d/kde konnten nicht gelesen werden.');
}else{

  if (pamlogin == "read"){
    if(login_pamlastlog == "fail" || login_pamlimits == "fail" || login_pamtally == "fail"){
      login_result = string("ne");
      if (login_pamlastlog == "fail")login_desc = string('pam_lastlog.so ist in der Konfigurationsdatei /etc/pam.d/login nicht gesetzt.');
      if (login_pamlimits == "fail")login_desc += string('\npam_limits.so ist in der Konfigurationsdatei /etc/pam.d/login nicht gesetzt.');
      if (login_pamtally == "fail")login_desc += string('\npam_tally.so ist in der Konfigurationsdatei /etc/pam.d/login nicht gesetzt.');
    }else if (login_pamlastlog != "fail" && login_pamlimits != "fail" && login_pamtally != "fail"){
      if (limits != "none" && limits != "empty" && limits != "novalentrys"){
        login_result = string("e");
        if (login_pamlastlog == "true")login_desc = string('pam_lastlog.so ist in der Konfigurationsdatei /etc/pam.d/login gesetzt.\nSie sollten aber auch die Option showfailed setzen, um Erfolglose Login-Versuche dem Benutzer beim Login zu melden.');
        else if (login_pamlastlog == "truefail")login_desc = string('pam_lastlog.so, pam_limits.so und pam_tally.so sind in der Konfigurationsdatei /etc/pam.d/login gesetzt.\n Folgende Eintr‰ge stehen in der Datei /etc/security/limits.conf:\n' + limits);
      }else{
        login_result = string("ne");
        if (limits == "none") val = "nicht vorhanden.";
        else if (limits == "empty") val = "leer.";
        else if (limits == "novalentrys") val = "nur mit auskommentierten Eintr‰gen gef¸llt.";
        login_desc = string('pam_lastlog.so, pam_limits.so und pam_tally.so sind in der Konfigurationsdatei /etc/pam.d/login gesetzt.\nAllerdings ist die Datei /etc/security/limits.conf ' + val);
      }
    } 
  
  }else{
    login_result = string("F");
    login_desc = string('Die Konfigurationsdatei /etc/pam.d/login wurde nicht gefunden');
  }
  if (pamsshd == "read"){
    if(sshd_pamlastlog == "fail" || sshd_pamlimits == "fail" || sshd_pamtally == "fail"){
      sshd_result = string("ne");
      if (sshd_pamlastlog == "fail")sshd_desc = string('pam_lastlog.so ist in der Konfigurationsdatei /etc/pam.d/sshd nicht gesetzt.');
      if (sshd_pamlimits == "fail")sshd_desc += string('\npam_limits.so ist in der Konfigurationsdatei /etc/pam.d/sshd nicht gesetzt.');
      if (sshd_pamtally == "fail")sshd_desc += string('\npam_tally.so ist in der Konfigurationsdatei /etc/pam.d/sshd nicht gesetzt.');
    }else if (sshd_pamlastlog != "fail" && sshd_pamlimits != "fail" && sshd_pamtally != "fail"){
      if (limits != "none" && limits != "empty" && limits != "novalentrys"){
        sshd_result = string("e");
        if (sshd_pamlastlog == "true")sshd_desc = string('pam_lastlog.so ist in der Konfigurationsdatei /etc/pam.d/sshd gesetzt.\nSie sollten aber auch die Option showfailed setzen, um Erfolglose Login-Versuche dem Benutzer beim login zu melden.');
        else if (sshd_pamlastlog == "truefail")sshd_desc = string('pam_lastlog.so, pam_limits.so und pam_tally.so sind in der Konfigurationsdatei /etc/pam.d/sshd gesetzt.\n Folgende Eintr‰ge stehen in der Datei /etc/security/limits.conf:\n' + limits);
      }else{
        sshd_result = string("ne");
        if (limits == "none") val = "nicht vorhanden.";
        else if (limits == "empty") val = "leer.";
        else if (limits == "novalentrys") val = "nur mit auskommentierten Eintr‰gen gef¸llt.";
        sshd_desc = string('pam_lastlog.so, pam_limits.so und pam_tally.so sind in der Konfigurationsdatei /etc/pam.d/sshd gesetzt.\nAllerdings ist die Datei /etc/security/limits.conf ' + val);
      }
    } 
  }else{
    sshd_result = string("F");
    sshd_desc = string('Die Konfigurationsdatei /etc/pam.d/sshd wurde nicht gefunden');  
  }
  if (pamgdm == "read"){
    if(gdm_pamlastlog == "fail" || gdm_pamlimits == "fail" || gdm_pamtally == "fail"){
      gdm_result = string("ne");
      if (gdm_pamlastlog == "fail")gdm_desc = string('pam_lastlog.so ist in der Konfigurationsdatei /etc/pam.d/gdm nicht gesetzt.');
      if (gdm_pamlimits == "fail")gdm_desc += string('\npam_limits.so ist in der Konfigurationsdatei /etc/pam.d/gdm nicht gesetzt.');
      if (gdm_pamtally == "fail")gdm_desc += string('\npam_tally.so ist in der Konfigurationsdatei /etc/pam.d/gdm nicht gesetzt.');
    }else if (gdm_pamlastlog != "fail" && gdm_pamlimits != "fail" && gdm_pamtally != "fail"){
      if (limits != "none" && limits != "empty" && limits != "novalentrys"){
        gdm_result = string("e");
        if (gdm_pamlastlog == "true")gdm_desc = string('pam_lastlog.so ist in der Konfigurationsdatei /etc/pam.d/gdm gesetzt.\nSie sollten aber auch die Option showfailed setzen, um Erfolglose Login-Versuche dem Benutzer beim login zu melden.');
        else if (gdm_pamlastlog == "truefail")gdm_desc = string('pam_lastlog.so, pam_limits.so und pam_tally.so sind in der Konfigurationsdatei /etc/pam.d/gdm gesetzt.\n Folgende Eintr‰ge stehen in der Datei /etc/security/limits.conf:\n' + limits);
      }else{
        gdm_result = string("ne");
        if (limits == "none") val = "nicht vorhanden.";
        else if (limits == "empty") val = "leer.";
        else if (limits == "novalentrys") val = "nur mit auskommentierten Eintr‰gen gef¸llt.";
        gdm_desc = string('pam_lastlog.so, pam_limits.so und pam_tally.so sind in der Konfigurationsdatei /etc/pam.d/gdm gesetzt.\nAllerdings ist die Datei /etc/security/limits.conf ' + val);
      }
    }  
  }else{
    gdm_result = string("nz");
    gdm_desc = string('Die Konfigurationsdatei /etc/pam.d/gdm wurde nicht gefunden');    
  }
  if (pamxdm == "read"){
    if(xdm_pamlastlog == "fail" || xdm_pamlimits == "fail" || xdm_pamtally == "fail"){
      xdm_result = string("ne");
      if (xdm_pamlastlog == "fail")xdm_desc = string('pam_lastlog.so ist in der Konfigurationsdatei /etc/pam.d/xdm nicht gesetzt.');
      if (xdm_pamlimits == "fail")xdm_desc += string('\npam_limits.so ist in der Konfigurationsdatei /etc/pam.d/xdm nicht gesetzt.');
      if (xdm_pamtally == "fail")xdm_desc += string('\npam_tally.so ist in der Konfigurationsdatei /etc/pam.d/xdm nicht gesetzt.');
    }else if (xdm_pamlastlog != "fail" && xdm_pamlimits != "fail" && xdm_pamtally != "fail"){
      if (limits != "none" && limits != "empty" && limits != "novalentrys"){
        xdm_result = string("e");
        if (xdm_pamlastlog == "true")xdm_desc = string('pam_lastlog.so ist in der Konfigurationsdatei /etc/pam.d/xdm gesetzt.\nSie sollten aber auch die Option showfailed setzen, um Erfolglose Login-Versuche dem Benutzer beim login zu melden.');
        else if (xdm_pamlastlog == "truefail")xdm_desc = string('pam_lastlog.so, pam_limits.so und pam_tally.so sind in der Konfigurationsdatei /etc/pam.d/xdm gesetzt.\n Folgende Eintr‰ge stehen in der Datei /etc/security/limits.conf:\n' + limits);
      }else{
        xdm_result = string("ne");
        if (limits == "none") val = "nicht vorhanden.";
        else if (limits == "empty") val = "leer.";
        else if (limits == "novalentrys") val = "nur mit auskommentierten Eintr‰gen gef¸llt.";
        xdm_desc = string('pam_lastlog.so, pam_limits.so und pam_tally.so sind in der Konfigurationsdatei /etc/pam.d/xdm gesetzt.\nAllerdings ist die Datei /etc/security/limits.conf ' + val);
      }
    }   
  }else{
    xdm_result = string("nz");
    xdm_desc = string('Die Konfigurationsdatei /etc/pam.d/xdm wurde nicht gefunden');      
  }
  if (pamkde == "read"){
    if(kde_pamlastlog == "fail" || kde_pamlimits == "fail" || kde_pamtally == "fail"){
      kde_result = string("ne");
      if (kde_pamlastlog == "fail")kde_desc = string('pam_lastlog.so ist in der Konfigurationsdatei /etc/pam.d/kde nicht gesetzt.');
      if (kde_pamlimits == "fail")kde_desc += string('\npam_limits.so ist in der Konfigurationsdatei /etc/pam.d/kde nicht gesetzt.');
      if (kde_pamtally == "fail")kde_desc += string('\npam_tally.so ist in der Konfigurationsdatei /etc/pam.d/kde nicht gesetzt.');
    }else if (kde_pamlastlog != "fail" && kde_pamlimits != "fail" && kde_pamtally != "fail"){
      if (limits != "none" && limits != "empty" && limits != "novalentrys"){
        kde_result = string("e");
        if (kde_pamlastlog == "true")kde_desc = string('pam_lastlog.so ist in der Konfigurationsdatei /etc/pam.d/kde gesetzt.\nSie sollten aber auch die Option showfailed setzen, um Erfolglose Login-Versuche dem Benutzer beim login zu melden.');
        else if (kde_pamlastlog == "truefail")kde_desc = string('pam_lastlog.so, pam_limits.so und pam_tally.so sind in der Konfigurationsdatei /etc/pam.d/kde gesetzt.\n Folgende Eintr‰ge stehen in der Datei /etc/security/limits.conf:\n' + limits);
      }else{
        kde_result = string("ne");
        if (limits == "none") val = "nicht vorhanden.";
        else if (limits == "empty") val = "leer.";
        else if (limits == "novalentrys") val = "nur mit auskommentierten Eintr‰gen gef¸llt.";
        kde_desc = string('pam_lastlog.so, pam_limits.so und pam_tally.so sind in der Konfigurationsdatei /etc/pam.d/kde gesetzt.\nAllerdings ist die Datei /etc/security/limits.conf ' + val);
      }
    }   
  }else{
    kde_result = string("nz");
    kde_desc = string('Die Konfigurationsdatei /etc/pam.d/kde wurde nicht gefunden');     
  }

  if (sshd_result == "ne" || sshd_result == "ne" || gdm_result == "ne" || xdm_result == "ne" || kde_result == "ne"){
    result = string("nicht erf¸llt");
    if (login_result == "ne") desc = login_desc;
    if (sshd_result == "ne") desc += '\n' + sshd_desc;
    if (gdm_result == "ne") desc += '\n' + gdm_desc;
    if (xdm_result == "ne") desc += '\n' + xdm_desc;
    if (kde_result == "ne") desc += '\n' + kde_desc;
  }else{ 
    result = string("erf¸llt");
    if (login_result != "ne") desc = login_desc;
    if (sshd_result != "ne") desc += '\n' + sshd_desc;
    if (gdm_result != "ne") desc += '\n' + gdm_desc;
    if (xdm_result != "ne") desc += '\n' + xdm_desc;
    if (kde_result != "ne") desc += '\n' + kde_desc;
  }


}

if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler auf bzw. es konnte kein Ergebnis ermittelt werden.'); 
}

set_kb_item(name:"GSHB-10/M4_015/result", value:result);
set_kb_item(name:"GSHB-10/M4_015/desc", value:desc);
set_kb_item(name:"GSHB-10/M4_015/name", value:name);

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

