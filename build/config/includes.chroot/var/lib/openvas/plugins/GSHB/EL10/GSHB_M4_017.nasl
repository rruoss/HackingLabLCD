###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_017.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 10. EL, Maﬂnahme 4.017
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
tag_summary = "IT-Grundschutz M4.017: Sperren und Lˆschen nicht benˆtigter Accounts und Terminals.

  Diese Pr¸fung bezieht sich auf die 10. Erg‰nzungslieferung (10. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
  Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

  http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04017.html";

if(description)
{
  script_id(94017);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Wed Apr 07 15:31:43 2010 +0200");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.017: Sperren und Lˆschen nicht benˆtigter Accounts und Terminals");
  
  if (! OPENVAS_VERSION)
  {
    desc = "Leider setzen Sie einen zu alte OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!";
    script_description(desc);
    script_summary("IT-Grundschutz M4.017: Sperren und Lˆschen nicht benˆtigter Accounts und Terminals.");
    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
    script_family("IT-Grundschutz-10");
    exit(0);
  }
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("IT-Grundschutz M4.017: Sperren und Lˆschen nicht benˆtigter Accounts und Terminals.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-10");
  script_mandatory_keys("Compliance/Launch/GSHB-10");
  script_dependencies("GSHB/GSHB_SSH_lastlogin.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.017: Sperren und Lˆschen nicht benˆtigter Accounts und Terminals\n';



if (! OPENVAS_VERSION)
  {
        set_kb_item(name:"GSHB-10/M4_017/result", value:"nicht zutreffend");
        set_kb_item(name:"GSHB-10/M4_017/desc", value:"Leider setzen Sie einen zu alte OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!");
        set_kb_item(name:"GSHB-10/M4_017/name", value:name);
    log_message(port:0, proto: "IT-Grundschutz", data:string("Leider setzen Sie einen zu alte OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!"));  
    exit(0);
}

gshbm =  "IT-Grundschutz M4.017: ";

lastlogin = get_kb_item("GSHB/lastlogin");
LockedUser = get_kb_item("GSHB/LockedUser");
UserShell = get_kb_item("GSHB/UserShell");
log = get_kb_item("GSHB/lastlogin/log");

ldapuser = get_kb_item("GSHB/lastLogonTimestamp/Userlist");
ldaplastlogin = get_kb_item("GSHB/lastLogonTimestamp");
ldaplog = get_kb_item("GSHB/lastLogonTimestamp/log");
WindowsDomainrole = get_kb_item("WMI/WMI_WindowsDomainrole");
OSNAME = get_kb_item("WMI/WMI_OSNAME");

maxnologindays = 84;

if(!find_in_path("perl"))perl = "notfound";


if(OSNAME >!< "none"){
  if(WindowsDomainrole < 4){
    result = string("nicht zutreffend");
    desc = string('Dieser Test kann bei Windows Systemen nur am Domaincontroller ausgef¸hrt werden.');
    if (ldaplog) desc += '\n' + ldaplog;
  }else{
    if (ldaplastlogin == "error"){
      result = string("Fehler");
      if (!ldaplog)desc = string('Beim Testen des Systems trat ein unbekannter Fehler auf.');
      if (ldaplog)desc = string('Beim Testen des Systems trat ein Fehler auf:\n' + ldaplog);
    }else{
      if (perl == "notfound"){
        result = string("Fehler");
        desc = string('Perl konnte im Suchpfad nicht gefunden werden. Es ist aber zur Berechnung des letzten Logins notwendig.');
      }
      else{
        val = split(ldaplastlogin, sep:";", keep:0);
        for(i=0; i<max_index(val); i++){
          userval = split(val[i], sep:",", keep:0);
          v=0;
          argv[v++] = "perl";
          argv[v++] = "-X";
          argv[v++] = "-e";
          argv[v++] = 'print ((' + userval[1] + '/864000000000) - 134773);';
          argv[v++] = '2>/dev/null';

          day1 = pread(cmd:"perl", argv:argv, cd:0);

          seconds = split(gettimeofday(), sep:".", keep:0);
          day2 = seconds[0] / 86400;
          day1 = split(day1, sep:".", keep:0);
          diffdays = int(day2) - int(day1[0]);
          if (diffdays > maxnologindays){
            Userlst += userval[0] + ' hat sich vor ' + diffdays + ' Tagen zum letzten mal angemeldet.\n';
          }
        }
        if (Userlst){
          result = string("nicht erf¸llt");
          desc = string('Nachfolgende Benutzer haben sich seit mehr als 12 Wochen nicht mehr angemeldet.\nSie sollten den/die Benutzer sperren oder lˆschen. Sollte der Benutzer ein Dienst/Daemon\n sein, pr¸fen Sie bitte ob er noch notwendig ist.\n' + Userlst);
        }else{
          result = string("erf¸llt");
          desc = string('Es konnten keine Benutzer gefunden werden, die sich seit mehr als 12 Wochen nicht angemeldet haben.');
        }
      }
    }
  }
}else if(lastlogin == "windows") {
    result = string("Fehler");
    desc = string('Das System scheint ein Windows-System zu sein wurde aber nicht richtig erkannt.');
}else if(lastlogin >< "error"){
  result = string("Fehler");
  if (!log)desc = string('Beim Testen des Systems trat ein unbekannter Fehler auf, siehe Log Message!');
  if (log)desc = string('Beim Testen des Systems trat ein Fehler auf:\n' + log);
}else{

  lastloginLst = split(lastlogin, keep:0);
  LockedUserLst = split(LockedUser, keep:0);
  UserShellLst = split(UserShell, keep:0);

  for(i=1; i<max_index(lastloginLst); i++){
    for(a=0; a<max_index(LockedUserLst); a++){
      lastloginUserLst = ereg_replace(string:lastloginLst[i], pattern:" {2,}", replace:":");
      lastloginUserLst = split(lastloginUserLst, sep:":", keep:0); 
      if (lastloginUserLst[0] == LockedUserLst[a]) continue;
      failuser += lastloginLst[i] + '\n';
    }
  }
  failuserLst = split(failuser, keep:0);
  for(i=1; i<max_index(failuserLst); i++){
    for(a=0; a<max_index(UserShellLst); a++){
      UserShellLstA = split(UserShellLst[a], sep:":", keep:0);
      failuserLstUserLst = ereg_replace(string:failuserLst[i], pattern:" {2,}", replace:":");
      failuserLstUserLst = split(failuserLstUserLst, sep:":", keep:0); 
      if (UserShellLstA[0] >!< failuserLstUserLst[0]) continue;
      resultuser += "Login-Shell: " + UserShellLstA[1] + " User: " + failuserLst[i] + '\n';
    }
  }
  if(!resultuser){
    result = string("erf¸llt");
    desc = string('Es konnten keine User gefunden werden, die sich seit mehr als 12 Wochen nicht angemeldet haben.');
  }else{
    result = string("nicht erf¸llt");
    desc = string('Nachfolgende User haben sich seit mehr als 12 Wochen nicht mehr angemeldet. \nSie sollten den/die User sperren oder lˆschen. Sollte der User ein Dienst/Deamon sein, \npr¸fen Sie bitte ob die vorgefundene Login-Shell notwendig ist.\n' + resultuser);
  }
}

set_kb_item(name:"GSHB-10/M4_017/result", value:result);
set_kb_item(name:"GSHB-10/M4_017/desc", value:desc);
set_kb_item(name:"GSHB-10/M4_017/name", value:name);

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

