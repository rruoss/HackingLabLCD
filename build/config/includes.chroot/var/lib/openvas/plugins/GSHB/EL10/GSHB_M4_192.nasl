###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_192.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 10. EL, Maﬂnahme 4.192
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
tag_summary = "IT-Grundschutz M4.192: Konfiguration des Betriebssystems f¸r einen Apache-Webserver (Win).

  Diese Pr¸fung bezieht sich auf die 10. Erg‰nzungslieferung (10. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
  Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

  http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04192.html";


if(description)
{
  script_id(94192);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Thu Jan 14 14:29:35 2010 +0100");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.192: Konfiguration des Betriebssystems f¸r einen Apache-Webserver (Win)");
  if (! OPENVAS_VERSION)
  {
    desc = "
    Leider setzen Sie einen zu alten OpenVAS Scan-Server ein.
    Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!";
    script_description(desc);
    script_summary("IT-Grundschutz M4.192: Konfiguration des Betriebssystems f¸r einen Apache-Webserver (Win).");
    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
    script_family("IT-Grundschutz-10");
    exit(0);
  }
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("IT-Grundschutz M4.192: Konfiguration des Betriebssystems f¸r einen Apache-Webserver (Win).");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-10");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-10");
  script_dependencies("GSHB/GSHB_WMI_Apache.nasl","GSHB/GSHB_Read_Apache_Config.nasl", "GSHB/GSHB_WMI_BootDrive.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  script_require_keys("WMI/Apache");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.192: Konfiguration des Betriebssystems f¸r einen Apache-Webserver (Win)\n';

if (! OPENVAS_VERSION)
{
        set_kb_item(name:"GSHB-10/M4_192/result", value:"nicht zutreffend");
        set_kb_item(name:"GSHB-10/M4_192/desc", value:"Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!");
        set_kb_item(name:"GSHB-10/M4_192/name", value:name);
    log_message(port:0, proto: "IT-Grundschutz", data:string("Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!"));  
    exit(0);
}


gshbm =  "IT-Grundschutz M4.192: ";

AP = get_kb_item("WMI/Apache");
APROOT = get_kb_item("WMI/Apache/RootPath");
APDOC = get_kb_item("GSHB/Apache/DocumentRoot");
APCLOG = get_kb_item("GSHB/Apache/CustomLog");
APELOG = get_kb_item("GSHB/Apache/ErrorLog");
FS = get_kb_item("WMI/FS");
OSDRIVE =get_kb_item("WMI/WMI_OSDRIVE");
log = get_kb_item("GSHB/ApacheConfig/log");
WMIOSLOG = get_kb_item("WMI/WMI_OS/log");



if (WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System."){
  result = string("nicht zutreffend");
  desc = string("Auf dem System l‰uft Samba, es ist kein Microsoft System.");
}else if("error" >< AP){
  result = string("Fehler");
  if (!log) desc = string("Beim Testen des Systems trat ein Fehler auf, siehe Log Message!");
  if (log) desc = string("Beim Testen des Systems trat ein Fehler auf: " +  log);
}else if("false" >< AP){
  result = string("nicht zutreffend");
  desc = string("Auf dem System ist kein Apache installiert.");
}
else
{
  FS = split(FS, sep:'\n', keep:0);
  APROOTSP = split(APROOT, sep:':', keep:0);
  APDOCSP = split(APDOC, sep:'|', keep:0);
  APCLOGSP = split(APCLOG, sep:'|', keep:0);
  APELOGSP = split(APELOG, sep:'|', keep:0);

  for(p=0; p<max_index(APDOCSP); p++)
  {
    if(APDOCSP[p])
    {
      APDOCLW = split(APDOCSP[p], sep:':', keep:0);
      if (APDOCLW[0] !~ "^[A-Za-z]$") APDOCFSLW = APROOTSP[0] + ':|NTFS';
      else APDOCFSLW = APDOCLW[0] + ':|NTFS';
      APDOCFSLW = toupper(APDOCFSLW);
      for(g=1; g<max_index(FS); g++)
      {
        APDOCFSLWRS = "NULL";
        if(APDOCLW[0] >< FS[g])
        {
          if (FS[g] >< APDOCFSLW)
          {
            APDOCFSLWRS = "TRUE";
          }
          else
          {
            APDOCFSLWRS = "FALSE";
          }
        }
        else
        {
          APDOCFSLWRS = "TRUE";
        }
      }
      if (APDOCLW[0] !~ "^[A-Za-z]$") APDOCFLW = APROOTSP[0] + ':';
      else APDOCFLW = APDOCLW[0] + ':';
      if (OSDRIVE >< APDOCFLW)
          {
            APDOCFLWRS = "FALSE";
          }
          else
          {
            APDOCFLWRS = "TRUE";
          }
    }
    else
    {
        APDOCFLWRS = "TRUE";
        APDOCFSLWRS = "TRUE";
    }
    if("FALSE" >< APDOCFSLWRS) NTFS = NTFS + APDOCSP[p] + ';';
    if("FALSE" >< APDOCFLWRS) DOCF = DOCF + APDOCFLW + ';';

  }
  if (!NTFS) NTFS = "TRUE";
  if (!DOCF) DOCF = "TRUE";
  for(c=0; c<max_index(APCLOGSP); c++)
  {
    if(APCLOGSP[c])
    {
      APCLOGLW = split(APCLOGSP[c], sep:':', keep:0);
      if (APCLOGLW[0] !~ "^[A-Za-z]$") APCLOGFLW = APROOTSP[0] + ':';
      else APCLOGFLW = APCLOGLW[0] + ':';
      APCLOGFLW = toupper(APCLOGFLW);
      OSDRIVE = toupper(OSDRIVE);

      if (OSDRIVE >< APCLOGFLW)
          {
            APCLOGFLWRS = "FALSE";
          }
      else
          {
            APCLOGFLWRS = "TRUE";
          }
    }
    else APCLOGFLWRS = "TRUE";
    if("FALSE" >< APCLOGFLWRS) CLOGF = CLOGF + APCLOGFLW + ';';
  }
  if (!CLOGF) CLOGF = "TRUE";

  for(e=0; e<max_index(APELOGSP); e++)
  {
    if(APELOGSP[e])
    {
      APELOGLW = split(APELOGSP[c], sep:':', keep:0);
      if (APELOGLW[0] !~ "^[A-Za-z]$") APELOGFLW = APROOTSP[0] + ':';
      else APELOGFLW = APELOGLW[0] + ':';
      APCLOGFLW = toupper(APELOGFLW);
      OSDRIVE = toupper(OSDRIVE);
      if (OSDRIVE >< APELOGFLW)
          {
            APELOGFLWRS = "FALSE";
          }
      else
          {
            APELOGFLWRS = "TRUE";
          }
    }
    else APELOGFLWRS = "TRUE";
    if("FALSE" >< APELOGFLWRS) ELOGF = ELOGF + APELOGFLW + ';';

  }
  if (!ELOGF) ELOGF = "TRUE";


  if (NTFS >< "TRUE" && DOCF >< "TRUE" && CLOGF >< "TRUE" && ELOGF >< "TRUE")
  {
    result = string("erf¸llt");
    desc = string("Auf dem System wurde der Apache Server gem‰ﬂ IT-Grundschutz M4.192: installiert.");
  }
  else
  {
    result = string("nicht erf¸llt");
    if (NTFS >!< "TRUE") desc = string('Das/Eines der Document Root(s) liegt nicht auf einem NTFS Laufwerk!\n');
    if (DOCF >!< "TRUE") desc = desc + string('Das/Eines der Document Root(s) liegt nicht auf einer eigenen Partition!\n');
    if (CLOGF >!< "TRUE") desc = desc + string('Das/Eines der Custom Logfile(s) liegt nicht auf einer eigenen Partition!\n');
    if (ELOGF >!< "TRUE") desc = desc + string('Das/Eines der Error Logfile(s) liegt nicht auf einer eigenen Partition!\n');
  }

}


set_kb_item(name:"GSHB-10/M4_192/result", value:result);
set_kb_item(name:"GSHB-10/M4_192/desc", value:desc);
set_kb_item(name:"GSHB-10/M4_192/name", value:name);

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
