###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_002.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 11. EL, Maßnahme 4.002
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
tag_summary = "IT-Grundschutz M4.002: Bildschirmsperre.

  Diese Prüfung bezieht sich auf die 11. Ergänzungslieferung (11. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Maßnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Ergänzungslieferung bezieht. Titel und Inhalt können sich bei einer
  Aktualisierung ändern, allerdings nicht die Kernthematik.

  Hinweis:

  Windows: Kann nur für Lokale Konten getestet werden.
  Linux: Nur voreingestellte Bildschirmschoner bei Gnome und KDE.

  http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04002.html";

if(description)
{
  script_id(894002);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Thu Feb 25 12:13:41 2010 +0100");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.002: Bildschirmsperre");
  
  if (! OPENVAS_VERSION)
  {
    desc = "Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!";
    script_description(desc);
    script_summary("IT-Grundschutz M4.002: Bildschirmsperre.");
    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
    script_family("IT-Grundschutz-11");
    exit(0);
  }
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("IT-Grundschutz M4.002: Bildschirmsperre.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-11");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-11");
  script_dependencies("GSHB/GSHB_WMI_ScreenSaver_Status.nasl", "GSHB/GSHB_WMI_OSInfo.nasl", "GSHB/GSHB_SSH_gnome_kde_screensaver.nasl");
  script_require_keys("WMI/Screensaver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.002: Bildschirmsperre\n';



if (! OPENVAS_VERSION)
  {
        set_kb_item(name:"GSHB-11/M4_002/result", value:"nicht zutreffend");
        set_kb_item(name:"GSHB-11/M4_002/desc", value:"Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!");
        set_kb_item(name:"GSHB-11/M4_002/name", value:name);
    log_message(port:0, proto: "IT-Grundschutz", data:string("Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!"));  
    exit(0);
}

gshbm =  "IT-Grundschutz M4.002: ";

OSNAME = get_kb_item("WMI/WMI_OSNAME");
Screensaver = get_kb_item("WMI/Screensaver");
log = get_kb_item("WMI/Screensaver/log");
Domainrole = get_kb_item("WMI/WMI_WindowsDomainrole");

gnomescreensaver = get_kb_item("GSHB/gnomescreensaver");
screensaverdaemon = get_kb_item("GSHB/screensaverdaemon");
defkdescreensav = get_kb_item("GSHB/defkdescreensav");
userkdescreensav = get_kb_item("GSHB/userkdescreensav");
sshlog = get_kb_item("GSHB/gnomescreensaver/log");

if(OSNAME >!< "none"){
  if(Screensaver >< "error"){
    result = string("Fehler");
    if (!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
    if (log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
  }else if(Screensaver >< "none" && Domainrole != "1"){
    result = string("Fehler");
    desc = string("Beim Testen des Systems trat ein Fehler auf,\nes konnten keine Einstellungen in der Registry\ngefunden werden.");
  }else if(Screensaver >< "none" && Domainrole == "1"){
    result = string("Fehler");
    desc = string("Beim Testen des Systems trat ein Fehler auf,\nes konnten keine Einstellungen in der Registry\ngefunden werden. Das liegt daran, dass das System\nDomainmitglied ist. Domainuser können nicht getestet\nwerden.");
  }else{

      Lst = split(Screensaver, sep:'\n', keep:0);
      for(i=0; i<max_index(Lst); i++)
      {
        screenresult = split(Lst[i], sep:";", keep:0);
        if ((screenresult[1] == "ScreenSaveActive=1" && screenresult[2] == "ScreenSaverIsSecure=1") || (screenresult[3] == "DomScreenSaveActive=1" && screenresult[3] == "DomScreenSaverIsSecure=1")){
          testval += 0;
        }else{
        testval += 1;
        faultusers +=  screenresult[0] + ";";
        }
      }
    if(Domainrole == 1){
      if(testval <= 0){
        result = string("unvollständig");
        desc = string('Es wurde für alle lokalen Benutzer die Bildschirm-\nsperre mit Passwortschutz aktiviert.Achtung,\nDomainuser können nicht getestet werden.');
      }else if(testval > 0){
        result = string("nicht erfüllt");
        desc = string('Für folgende lokalen Benutzer ist die Bildschirmsperre\nmit Passwortschutz nicht aktiviert:\n' + faultusers + '\nAchtung, Domainuser können nicht getestet werden.');
      } 
    }
    else{   
      if(testval <= 0){
        result = string("erfüllt");
        desc = string("Es wurde für alle Benutzer die Bildschirmsperre mit\nPasswortschutz aktiviert.");
      }else if(testval > 0){
        result = string("nicht erfüllt");
        desc = string('Für folgende Benutzer ist die Bildschirmsperre mit\nPasswortschutz nicht aktiviert:\n' + faultusers);
      } 
    }
  }
}
else if (gnomescreensaver != "none" && gnomescreensaver != "windows"){
  if(gnomescreensaver >< "error"){
    result = string("Fehler");
    if (!sshlog) desc = string("Beim Testen des Systems trat ein Fehler auf, siehe Log Message.");
    if (sshlog) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + sshlog);
  }else if(gnomescreensaver == "true" && screensaverdaemon != "false"){
     result = string("erfüllt");
     desc = string("Es wurde die Bildschirmsperre mit Passwortschutz\naktiviert.");
     if (screensaverdaemon == "none") desc += string('\nDer Schlüsselname /apps/gnome_settings_daemon/\nscreensaver/start_screensaver wurde nicht gefunden.');
  }else if(gnomescreensaver == "true" && screensaverdaemon == "false"){
     result = string("nicht erfüllt");
     desc = string('Es wurde die Bildschirmsperre mit Passwortschutz\naktiviert. Allerdings steht der Schlüsselname /apps/\ngnome_settings_daemon/screensaver/start_screensaver\nauf false. Setzen Sie diesen Wert auf »True«, um den\nBildschirmschoner beim Anmelden zu starten.');
  }else {
     result = string("nicht erfüllt");
     desc = string("Es wurde keine Bildschirmsperre mit Passwortschutz\naktiviert.");
  }

}

else if (defkdescreensav != "none" && defkdescreensav != "windows"){
  if(defkdescreensav >< "error"){
    result = string("Fehler");
    if (!sshlog) desc = string("Beim Testen des Systems trat ein Fehler auf,\nsiehe Log Message.");
    if (sshlog) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + sshlog);
  }else if(defkdescreensav == "true" && userkdescreensav == "true"){
     result = string("erfüllt");
     desc = string("Es wurde die Bildschirmsperre mit Passwortschutz\naktiviert.");
  }else if(defkdescreensav == "false" && userkdescreensav == "true"){
     result = string("unvollständig");
     desc = string('Es wurde die Bildschirmsperre mit Passwortschutz bei\nallen Usern aktiviert. Allerdings wurde die\nBildschirmsperre mit Passwortschutz in der Datei\n/etc/kde4/share/config/kscreensaverrc nicht richtig\nkonfiguriert.');
  }else if(defkdescreensav == "true" && userkdescreensav == "false"){
     result = string("nicht erfüllt");
     desc = string("Es gibt User bei denen die Bildschirmsperre mit\nPasswortschutz nicht aktiviert ist.");
  }
}
else if(defkdescreensav >< "windows" || gnomescreensaver >< "windows" ) {
    result = string("Fehler");
    if (OSNAME >!< "none" && OSNAME >!< "error") desc = string('Folgendes System wurde erkannt:\n' + OSNAME + '\nAllerdings konnte auf das System nicht korrekt\nzugegriffen werden. Folgende Fehler sind aufgetreten:\n' + log);
    else desc = string('Das System scheint ein Windows-System zu sein.\nAllerdings konnte auf das System nicht korrekt\nzugegriffen werden. Folgende Fehler sind aufgetreten:\n' + log);
  }
else{
  result = string("Fehler");
  desc = string('Es wurde versucht, die Konfiguration der Bildschirmsperre mit\nPasswortschutz, auf dem System zu erkennen. Dabei wurde auf\nWindows, GNOME und KDE Standardeinstellungen getestet. Keines\nder Systeme konnte dabei aufgrund von Standardeinstellungen\nerkannt werden.');
}
if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler\nauf bzw. es konnte kein Ergebnis ermittelt werden.'); 
}
set_kb_item(name:"GSHB-11/M4_002/result", value:result);
set_kb_item(name:"GSHB-11/M4_002/desc", value:desc);
set_kb_item(name:"GSHB-11/M4_002/name", value:name);

silence = get_kb_item("GSHB-11/silence");

if (silence){
exit(0);
} else {
  report = 'Ergebnisse zum IT-Grundschutz, 11. Ergänzungslieferung:\n\n';
  report = report + name + 'Ergebnis:\t' + result +
           '\nDetails:\t' + desc + '\n\n';
    if ("nicht erfüllt" >< result || result >< "Fehler"){
    security_hole(port:0, proto: "IT-Grundschutz", data:report);
    } else if (result >< "unvollständig"){
    security_warning(port:0, proto: "IT-Grundschutz", data:report);
    } else if (result >< "erfüllt" || result >< "nicht zutreffend"){
    security_note(port:0, proto: "IT-Grundschutz", data:report);
    }
exit(0);
}
