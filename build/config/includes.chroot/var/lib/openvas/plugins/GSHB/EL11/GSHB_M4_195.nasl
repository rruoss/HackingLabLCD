###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_195.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 11. EL, Maﬂnahme 4.195
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
tag_summary = "IT-Grundschutz M4.195: Konfiguration der Zugriffssteuerung beim Apache-Webserver (Win).

  Diese Pr¸fung bezieht sich auf die 11. Erg‰nzungslieferung (11. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
  Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

  http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04195.html";


if(description)
{
  script_id(894195);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Thu Jan 14 14:29:35 2010 +0100");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.195: Konfiguration der Zugriffssteuerung beim Apache-Webserver (Win)");
  if (! OPENVAS_VERSION)
  {
    desc = "
    Leider setzen Sie einen zu alten OpenVAS Scan-Server ein.
    Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!";
    script_description(desc);
    script_summary("IT-Grundschutz M4.195: Konfiguration der Zugriffssteuerung beim Apache-Webserver (Win).");
    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
    script_family("IT-Grundschutz-11");
    exit(0);
  }
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("IT-Grundschutz M4.195: Konfiguration der Zugriffssteuerung beim Apache-Webserver (Win).");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-11");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-11");
  script_dependencies("GSHB/GSHB_WMI_Apache.nasl","GSHB/GSHB_Read_Apache_Config.nasl","GSHB/GSHB_Read_Apache_htaccessfiles.nasl" ,  "GSHB/GSHB_WMI_OSInfo.nasl");
  script_require_keys("WMI/Apache");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.195: Konfiguration der Zugriffssteuerung beim Apache-Webserver (Win)\n';

if (! OPENVAS_VERSION)
{
        set_kb_item(name:"GSHB-11/M4_195/result", value:"nicht zutreffend");
        set_kb_item(name:"GSHB-11/M4_195/desc", value:"Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!");
        set_kb_item(name:"GSHB-11/M4_195/name", value:name);
    log_message(port:0, proto: "IT-Grundschutz", data:string("Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!"));  
    exit(0);
}


gshbm =  "IT-Grundschutz M4.195: ";
WMIOSLOG = get_kb_item("WMI/WMI_OS/log");
AP = get_kb_item("WMI/Apache");
APROOT = get_kb_item("GSHB/Apache/RootPath");
APROOT = ereg_replace(pattern:'\\\\', replace:'/', string:APROOT);
APROOT = tolower(APROOT);
APDOC = get_kb_item("GSHB/Apache/DocumentRoot");
APDOC = tolower(APDOC);
APACPWD = get_kb_item("GSHB/Apache/AccessPWD");
APACPWD = tolower(APACPWD);
OSDRIVE =get_kb_item("WMI/WMI_OSDRIVE");
ALLOW = get_kb_item("GSHB/Apache/AllowFrom");
log = get_kb_item("GSHB/ApacheConfig/log");

if (WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System."){
  result = string("nicht zutreffend");
  desc = string("Auf dem System l‰uft Samba,\nes ist kein Microsoft Windows System.");
}else if("error" >< AP){
  result = string("Fehler");
  if (!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
  if (log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" +  log);
}else if("false" >< AP){
  result = string("nicht zutreffend");
  desc = string("Auf dem System ist kein Apache installiert.");
}
else
{
  APACPWD = split(APACPWD, sep:'|', keep:0);
  APDOC = split(APDOC, sep:'|', keep:0);
  for(p=0; p<max_index(APACPWD); p++)
  {
    for(a=0; a<max_index(APDOC); a++)
    {
      if (!APDOC[a]) continue;
      if(APDOC[a] !~ "^[A-Za-z]:") APDOCPATH = APROOT + APDOC[a];
      else APDOCPATH = APDOC[a];
      if (APDOCPATH >< APACPWD[p])
      {
      PWDROOT = "FALSE";
      }
      else
      {
      PWDROOT = "TRUE";
      }
    }
    if ("FALSE" >< PWDROOT) PWDROOTSUM = PWDROOTSUM + APACPWD[p];
  }
#  set_kb_item(name:"GSHB-11/M4_195/PWDROOTSUM", value:PWDROOTSUM);#TEST

  ALLOW = tolower(ALLOW);
  ALLOW = split(ALLOW, sep:'|', keep:0);

  for(w=0; w<max_index(ALLOW); w++)
  {
#    set_kb_item(name:"GSHB-11/M4_195/ALLOW " + w, value:ALLOW[w]);#TEST
    if (!ALLOW[w]) continue;
    if (ALLOW[w] >< "allow from all") ALLOWRS = "FALSE";
    #else if (ALLOW[w] =~ "allow from (25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)") ALLOWRS = "TRUE";
    else if (ALLOW[w] =~ "allow from (25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.?") ALLOWRS = "TRUE";
    else if (ALLOW[w] =~ "allow from (:[\w-]+\.)+[a-z]{2,7}$") ALLOWRS = "FALSE";
    else ALLOWRS = "TRUE";
    if ("FALSE" >< ALLOWRS) ALLOWRSSUM = ALLOWRSSUM + ALLOW[w] + ';';
  }
  if (PWDROOTSUM >< "TRUE" && ALLOWRSSUM >< "TRUE")
  {
    result = string("erf¸llt");
    desc = string("Auf dem System wurde der Apache Server gem‰ﬂ IT-Grundschutz M4.195: installiert.");
  }
  else
  {
    result = string("nicht erf¸llt");
    if (PWDROOTSUM >!< "TRUE") desc = string('htpasswd-Dateien befinden sich innerhalb des\nWWW-Dateibaums.\n');
    if (ALLOWRSSUM >!< "TRUE") desc = desc + string('Es wurde keine Zugriffsbeschr‰nkungen oder\nZugriffsbeschr‰nkungen auf Domainbasis hinterlegt.');
  }
}


set_kb_item(name:"GSHB-11/M4_195/result", value:result);
set_kb_item(name:"GSHB-11/M4_195/desc", value:desc);
set_kb_item(name:"GSHB-11/M4_195/name", value:name);

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
