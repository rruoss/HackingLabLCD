##############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_055.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 10. EL, Maﬂnahme 4.055
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
tag_summary = "IT-Grundschutz M4.055: Sichere Installation von Windows NT (Win)

  Diese Pr¸fung bezieht sich auf die 10. Erg‰nzungslieferung (10. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
  Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

  http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04055.html";


if(description)
{
  script_id(94055);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Thu Jan 14 14:29:35 2010 +0100");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.055: Sichere Installation von Windows NT (Win)");
  if (! OPENVAS_VERSION)
  {
    desc = "
    Leider setzen Sie einen zu alten OpenVAS Scan-Server ein.
    Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!";
    script_description(desc);
    script_summary("IT-Grundschutz M4.055: Sichere Installation von Windows NT (Win)");
    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
    script_family("IT-Grundschutz-10");
    exit(0);
  }
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("IT-Grundschutz M4.055: Sichere Installation von Windows NT (Win)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-10");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-10");
#  script_dependencies("GSHB/GSHB_WMI_WIN_Subsystem.nasl", "GSHB/GSHB_WMI_Loginscreen.nasl");
  script_dependencies("GSHB/GSHB_WMI_WIN_Subsystem.nasl", "GSHB/GSHB_WMI_PolSecSet.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  script_require_keys("WMI/SessionManagerOS2",
  "WMI/SessionManagerPosix", "WMI/OS2", "WMI/Posix", "WMI/DontDisplayLastUserName", "WMI/LegalNoticeCaption",
  "WMI/LegalNoticeText");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.055: Sichere Installation von Windows NT (Win)\n';

if (! OPENVAS_VERSION)
{
        set_kb_item(name:"GSHB-10/M4_055/result", value:"nicht zutreffend");
        set_kb_item(name:"GSHB-10/M4_055/desc", value:"Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!");
        set_kb_item(name:"GSHB-10/M4_055/name", value:name);
    log_message(port:0, proto: "IT-Grundschutz", data:string("Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!"));  
    exit(0);
}



os2 = get_kb_item("WMI/OS2");
posix = get_kb_item("WMI/Posix");
os2sess = get_kb_item("WMI/SessionManagerOS2");
posixsess = get_kb_item("WMI/SessionManagerPosix");
winversmb = get_kb_item("SMB/WindowsVersion");
winverwmi = get_kb_item("WMI/WMI_OSVER");
ddlun = get_kb_item("WMI/DontDisplayLastUserName");
lnc = get_kb_item("WMI/LegalNoticeCaption");
lnt = get_kb_item("WMI/LegalNoticeText");
log = get_kb_item("WMI/cps/GENERAL/log");
WMIOSLOG = get_kb_item("WMI/WMI_OS/log");

gshbm = "GSHB Maﬂnahme 4.055: ";

# Start der ‹berpr¸fung ob der OS2 und Posix Sessionmanager korrekt deinstalliert wurde
# Sollte die Windows Version grˆﬂer 5.0 sein, wird der Test ¸bersprungen, da nicht von Bedeutung.
#if(winver > '5.0'){
if((winversmb > '5.0' || winverwmi > '5.0') || (!winversmb && !winverwmi)){
  M455sr = "nicht zutreffend";
   if (!winversmb && !winverwmi){
     M455sd = "Das Systems wurde nicht getestet, da es anscheinend kein Windows System ist.";
   }else {
     M455sd = "Subsysteme ohne Bedeutung da nicht Windows NT/Windows 2000!";
   }
} else {

        if (os2sess >< "error" && posixsess >< "error" && ddlun >< "error" && lnc >< "error" && lnt >< "error" && os2 >< "error" && posix >< "error"){
                M455sr = "Fehler";
                M455lr = M455sr;
                if (!log) M455sd = "Beim Testen des Systems trat ein Fehler auf, siehe Log Message!";
                if (log) M455sd = "Beim Testen des Systems trat ein Fehler auf: " + log;
                M455ld = M455sd;
        } else if (os2sess >< "inapplicable" && posixsess >< "inapplicable" && ddlun >< "inapplicable" && lnc >< "inapplicable" && lnt >< "inapplicable" && os2 >< "inapplicable" && posix >< "inapplicable"){
                M455sr = "Nicht zutreffend";
                M455lr = M455sr;
                M455sd = "Das Systems wurde nicht getestet, da es anscheinend kein Windows System ist.";
                M455ld = M455sd;
        } else {  if(os2sess >< "on" || posixsess >< "on"){
                        M455srr = "nicht erf¸llt";
                        M455srd = "Der Session Manager OS2 ist " + os2sess + " und Posix ist " + posixsess + ". Dementsprechend sind sie NICHT in der Registry deaktiviert!";
                } if(os2 >< "on"){
                        M455os2r = "nicht erf¸llt";
                        M455os2d = "Der Session Manager OS2 ist NICHT deinstalliert!";
                } else {M455os2r = "erf¸llt";
                        M455os2d = "Der Session Manager OS2 ist deinstalliert!";
                        }
                if(posix >< "on"){
                        M455posr = "nicht erf¸llt";
                        M455posd = "Der Session Manager Posix ist NICHT deinstalliert!";
                } else {M455posr = "erf¸llt";
                        M455posd = "Der Session Manager Posix ist deinstalliert!";
                        }
                if(os2sess >< "off" && posixsess >< "off"){
                        M455ssr = "erf¸llt";
                        M455srd = "Session Manager OS und Posix sind in der Registry deaktiviert!";
                } if (M455srr >< "erf¸llt" && M455os2r >< "erf¸llt" && M455posr >< "erf¸llt"){
                        M455sr = "erf¸llt";
                        M455sd = "Session Manager OS und Posix sind entfernt und in der Registry deaktiviert!";
                } else if (M455srr >< "nicht erf¸llt" || M455os2r >< "nicht erf¸llt" || M455posr >< "nicht erf¸llt"){
                        M455sr = "nicht erf¸llt";
                        M455sd = M455srd + string("\n") + M455os2d + string("\n") + M455posd;
                }
        }
}


# Start der ‹berpr¸fung ob die Windows Anmeldung korrekt installiert wurde

if(ddlun >< "on" && lnc >< "on" && lnt >< "on"){
  M455lr = "erf¸llt";
  M455ld = "Das Anzeigen des letzten Benutzers wurde in der Registry deaktiviert und eine Warnung vor dem Login hinterlegt!";
} else if(ddlun >< "inapplicable" && lnc >< "inapplicable" && lnt >< "inapplicable"){
    M455lr = "nicht zutreffend";
    M455ld = "Das Systems wurde nicht getestet, da es anscheinend kein Windows System ist.";
} else if(ddlun >< "error" && lnc >< "error" && lnt >< "error"){
    M455lr = "Fehler";
    if (!log) M455ld = "Beim Testen des Systems trat ein Fehler auf, siehe Log Message!";
    if (log) M455ld = "Beim Testen des Systems trat ein Fehler auf: " + log;
} else if(ddlun >< "off" || lnc >< "off" || lnt >< "off"){
    M455lr = "nicht erf¸llt";
        if(ddlun >< "off" && lnc >< "on" && lnt >< "on"){
          M455ld = "Das anzeigen des letzten Benutzers wurde in der Registry NICHT deaktiviert allerdings wurde eine Warnung vor dem Login hinterlegt!";
        }else{
                if(ddlun >< "on" && (lnc >< "off" || lnt >< "off")){
                  M455ld =  "Das anzeigen des letzten Benutzers wurde in der Registry deaktiviert allerdings wurde KEINE Warnung vor dem Login hinterlegt!";
                }else{
                M455ld = "Das anzeigen des letzten Benutzers wurde in der Registry NICHT deaktiviert und es wurde KEINE Warnung vor dem Login hinterlegt!";

        }
    }
}

# Ausgaben erzeugen

if (M455sr >< "erf¸llt" && M455lr >< "erf¸llt"){
        desc = M455sd + string("\n") + M455ld;
        result = string("erf¸llt");
} else if (M455sr >< "nicht zutreffend" && M455lr >< "nicht zutreffend"){
        desc = M455ld;
        result = string("nicht zutreffend");
} else if (M455sr >< "nicht zutreffend" && M455lr >< "erf¸llt"){
        desc = M455sd + string("\n") + M455ld;
        result = string("erf¸llt");
} else if (M455sr >< "nicht erf¸llt" || M455lr >< "nicht erf¸llt"){
        desc = M455sd + string("\n") + M455ld;
        result = string("nicht erf¸llt");
} else if (M455sr >< "Fehler" || M455lr >< "Fehler"){
        desc = M455ld;
        result = string("Fehler");
}

if (WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System."){
  result = string("nicht zutreffend");
  desc = string("Auf dem System l‰uft Samba, es ist kein Microsoft System.");
}

set_kb_item(name:"GSHB-10/M4_055/result", value:result);
set_kb_item(name:"GSHB-10/M4_055/desc", value:desc);
set_kb_item(name:"GSHB-10/M4_055/name", value:name);

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
