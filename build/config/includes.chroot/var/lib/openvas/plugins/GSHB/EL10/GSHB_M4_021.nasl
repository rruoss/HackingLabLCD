###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_021.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 10. EL, Maﬂnahme 4.021
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
tag_summary = "IT-Grundschutz M4.021: Verhinderung des unautorisierten Erlangens von Administratorrechten.

  Diese Pr¸fung bezieht sich auf die 10. Erg‰nzungslieferung (10. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
  Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

  http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04021.html";

if(description)
{
  script_id(94021);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Tue Apr 13 14:21:58 2010 +0200");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.021: Verhinderung des unautorisierten Erlangens von Administratorrechten");
  
  if (! OPENVAS_VERSION)
  {
    desc = "Leider setzen Sie einen zu alte OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!";
    script_description(desc);
    script_summary("IT-Grundschutz M4.021: Verhinderung des unautorisierten Erlangens von Administratorrechten.");
    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
    script_family("IT-Grundschutz-10");
    exit(0);
  }
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("IT-Grundschutz M4.021: Verhinderung des unautorisierten Erlangens von Administratorrechten.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-10");
  script_mandatory_keys("Compliance/Launch/GSHB-10");
  script_dependencies("GSHB/GSHB_SSH_prev_root_login.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.021: Verhinderung des unautorisierten Erlangens von Administratorrechten\n';



if (! OPENVAS_VERSION)
  {
        set_kb_item(name:"GSHB-10/M4_021/result", value:"nicht zutreffend");
        set_kb_item(name:"GSHB-10/M4_021/desc", value:"Leider setzen Sie einen zu alte OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!");
        set_kb_item(name:"GSHB-10/M4_021/name", value:name);
    log_message(port:0, proto: "IT-Grundschutz", data:string("Leider setzen Sie einen zu alte OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!"));  
    exit(0);
}

gshbm =  "IT-Grundschutz M4.021: ";


ttynonconsole = get_kb_item("GSHB/securetty/nonconsole");
SSHDPermitRootLogin = get_kb_item("GSHB/sshdconfig/PermitRootLogin");
syslogsuenab = get_kb_item("GSHB/logindefs/syslogsuenab");
nfsexports = get_kb_item("GSHB/nfsexports");
nfsnorootsquash = get_kb_item("GSHB/nfsexports/norootsquash");
nfsrootsquash = get_kb_item("GSHB/nfsexports/rootsquash");
permsecuretty = get_kb_item("GSHB/securetty/perm");
permsshdconfig = get_kb_item("GSHB/sshdconfig/perm");
permlogindefs = get_kb_item("GSHB/logindefs/perm");
log = get_kb_item("GSHB/securetty/log");
uname = get_kb_item("GSHB/uname");

   
OSNAME = get_kb_item("WMI/WMI_OSNAME");

if(OSNAME >!< "none"){
  result = string("nicht zutreffend");
  desc = string('Dieser Test bezieht sich auf UNIX/LINUX Systeme. Das System ist ein ' + OSNAME + ' System.');
}else if(ttynonconsole == "windows") {
    result = string("nicht zutreffend");
    desc = string('Dieser Test bezieht sich auf UNIX/LINUX Systeme. Das System scheint ein Windows-System zu sein.');
}else if(ttynonconsole >< "error"){
  result = string("Fehler");
  if (!log)desc = string('Beim Testen des Systems trat ein unbekannter Fehler auf.');
  if (log)desc = string('Beim Testen des Systems trat ein Fehler auf:\n' + log);
}
#################
if (result != "nicht zutreffend" && result != "Fehler"){
  if(ttynonconsole >< "none" || SSHDPermitRootLogin >< "none" || syslogsuenab >< "none" || nfsexports >< "none" || securetty == "nocat" || sshdconfig == "nocat" || logindefs == "nocat" || nfsexports == "nocat"){
    if(ttynonconsole >< "none" && uname !~ "SunOS.*"){
      result_tty = string("Fehler");
      desc = string('Fehler: Beim Testen des Systems wurde festgestellt, dass die Datei /etc/securetty nicht gefunden werden konnte.\n');
    }
    if(SSHDPermitRootLogin >< "none"){
      result_sshd = string("Fehler");
      desc += string('Fehler: Beim Testen des Systems wurde festgestellt, dass die Datei /etc/ssh/sshd_config nicht gefunden werden konnte.\n');
    }
    if(syslogsuenab >< "none" && uname !~ "SunOS.*"){
      result_syslog = string("Fehler");
      desc += string('Fehler: Beim Testen des Systems wurde festgestellt, dass die Datei /etc/login.defs nicht gefunden werden konnte.\n');
    }
    if(nfsexports >< "none" && uname !~ "SunOS.*"){
      result_nfs = string("Fehler");
      desc += string('Fehler: Beim Testen des Systems wurde festgestellt, dass die Datei /etc/exports nicht gefunden werden konnte.\n');
    }
 
    if(securetty == "nocat" || sshdconfig == "nocat" || logindefs == "nocat" || nfsexports == "nocat"){
      result_tty = string("Fehler");
      result_nfs = string("Fehler");
      result_sshd = string("Fehler");
      result_nfs = string("Fehler");
      desc = string('Fehler: Beim Testen des Systems wurde der Befehl cat nicht gefunden.\n'); 
    }
  }
#################
    if(uname !~ "SunOS.*"){
      if (ttynonconsole >< "noperm"){
        result_tty = string("Fehler");
        desc += string('Fehler: Beim Testen des Systems wurde festgestellt, dass Sie keine Berechtigung haben die Datei /etc/securetty zu lesen.\n'); 
      }else if(ttynonconsole >< "secure"){
        result_tty = "ok";
        desc += string('Beim Testen des Systems wurden keine fehlerhafte Eintr‰ge in der Datei /etc/securetty gefunden.\n'); 
      }else {
        result_tty = "fail";
        desc += string('Fehler: Beim Testen des Systems wurden folgende zu entfernende Eintr‰ge in der Datei /etc/securetty gefunden:\n' + ttynonconsole + '\n'); 
      }
    }
#################  
    if (SSHDPermitRootLogin >< "noperm"){
      result_sshd = string("Fehler");
      desc += string('Fehler: Beim Testen des Systems wurde festgestellt, dass Sie keine Berechtigung haben die Datei /etc/ssh/sshd_config zu lesen.\n'); 
    }else if(SSHDPermitRootLogin == "norootlogin"){
      result_sshd = "ok";
      desc += string('Beim Testen des Systems wurde festgestellt, dass PermitRootLogin in der Datei /etc/ssh/sshd_config auf no gesetzt ist.\n'); 
    }else if(SSHDPermitRootLogin == "rootlogin"){
      result_sshd = "fail";
      desc += string('Fehler: Beim Testen des Systems wurde festgestellt, dass PermitRootLogin in der Datei /etc/ssh/sshd_config auf yes gesetzt ist. ƒndern Sie den Wert wenn mˆglich auf no.\n'); 
    } 
#################
    if(uname !~ "SunOS.*"){
      if (syslogsuenab >< "noperm"){
        result_syslog = string("Fehler");
        desc += string('Fehler: Beim Testen des Systems wurde festgestellt, dass Sie keine Berechtigung haben die Datei /etc/login.defs zu lesen.\n'); 
      }else if(syslogsuenab == "syslogsuenab"){
        result_syslog = "ok";
        desc += string('Beim Testen des Systems wurde festgestellt, dass SYSLOG_SU_ENAB in der Datei /etc/login.defs auf yes gesetzt ist.\n'); 
      }else if(syslogsuenab == "nosyslogsuenab"){
        result_syslog = "fail";
        desc += string('Fehler: Beim Testen des Systems wurde festgestellt, dass SYSLOG_SU_ENAB in der Datei /etc/login.defs auf no gesetzt ist. ƒndern Sie den Wert wenn mˆglich auf yes.\n');
      }
    }
#################
    if(uname !~ "SunOS.*"){
      if (nfsexports >< "noperm"){
        result_nfs = string("Fehler");
        desc += string('Fehler: Beim Testen des Systems wurde festgestellt, dass Sie keine Berechtigung haben die Datei /etc/exports zu lesen.\n'); 
      }else if(nfsnorootsquash != "none"){
        result_nfs = "fail";
        desc += string('Fehler: Beim Testen des Systems wurde festgestellt, dass der Eintrag root_squash in der Datei /etc/exports bei folgenden Eintr‰gen fehlt:\n' + nfsnorootsquash); 
      }else if(nfsnorootsquash == "none" && nfsrootsquash != "none"){
        result_nfs = "ok";
        desc += string('Beim Testen des Systems wurde festgestellt, dass der Eintrag root_squash in der Datei /etc/exports bei allen Eintr‰gen gesetzt ist.\n'); 
      }else if(nfsnorootsquash == "none" && nfsrootsquash == "none"){
        result_nfs = "ok";
        desc += string('Beim Testen des Systems wurde festgestellt, dass keine Eintr‰ge/Freigaben in der Datei /etc/exports gibt.\n'); 
      }
    }
#################
  if(permsecuretty == "none" || permsshdconfig == "none" || permlogindefs == "none"){
    if(permsecuretty == "none" && uname !~ "SunOS.*"){
      result_permsecuretty = string("Fehler");
      if (result_tty != "Fehler")desc += string('Fehler: Beim Testen des Systems wurde festgestellt, dass die Datei /etc/securetty nicht gefunden werden konnte.\n');
    }
    if(permsshdconfig == "none"){
      result_permsshdconfig = string("Fehler");
      if (result_sshd != "Fehler")desc += string('Fehler: Beim Testen des Systems wurde festgestellt, dass die Datei /etc/ssh/sshd_config nicht gefunden werden konnte.\n');
    }
    if(permlogindefs == "none" && uname !~ "SunOS.*"){
      result_permlogindefs = string("Fehler");
      if (result_syslog != "Fehler")desc += string('Fehler: Beim Testen des Systems wurde festgestellt, dass die Datei /etc/login.defs nicht gefunden werden konnte.\n');
    }
  }
#################
  if(permsecuretty != "none"){
    if (permsecuretty =~ "-rw-(r|-)--(r|-)--.*"){
      result_permsecuretty = string("ok");
      desc += string('Beim Testen des Systems wurden f¸r die Datei /etc/securetty folgende korrekte Sicherheiteinstellungen festgestellt: ' + permsecuretty + '\n'); 
    }
    else{
      result_permsecuretty = string("fail");
      desc += string('Fehler: Beim Testen des Systems wurden f¸r die Datei /etc/securetty folgende fehlerhafte Sicherheiteinstellungen festgestellt: ' + permsecuretty + '\nBitte ‰ndern Sie diese auf "-rw-r--r--".\n' ); 
    }
#################
  } 
  if(permsshdconfig != "none"){
    if (permsshdconfig =~ "-rw-(r|-)--(r|-)--.*"){
      result_permsshdconfig = string("ok");
      desc += string('Beim Testen des Systems wurden f¸r die Datei /etc/ssh/sshd_config folgende korrekte Sicherheiteinstellungen festgestellt: ' + permsshdconfig + '\n'); 
    }
    else{
      result_permsshdconfig = string("fail");
      desc += string('Fehler: Beim Testen des Systems wurden f¸r die Datei /etc/ssh/sshd_config folgende fehlerhafte Sicherheiteinstellungen festgestellt: ' + permsshdconfig + '\nBitte ‰ndern Sie diese auf "-rw-r--r--".\n' ); 
    }
#################
  }
  if(permlogindefs != "none"){
    if (permlogindefs =~ "-rw-(r|-)--(r|-)--.*"){
      result_permlogindefs = string("ok");
      desc += string('Beim Testen des Systems wurden f¸r die Datei /etc/login.defs folgende korrekte Sicherheiteinstellungen festgestellt: ' + permsecuretty + '\n'); 
    }
    else{
      result_permlogindefs = string("fail");
      desc += string('Fehler: Beim Testen des Systems wurden f¸r die Datei /etc/login.defs folgende fehlerhafte Sicherheiteinstellungen festgestellt: ' + permsecuretty + '\nBitte ‰ndern Sie diese auf "-rw-r--r--".\n' ); 
    }
  } 
#################
  if(!result && (result_tty == "fail" ||  result_sshd == "fail" || result_syslog == "fail" || result_nfs == "fail" || result_permsecuretty == "fail" || result_permsshdconfig == "fail" || result_permlogindefs == "fail")) result = string("nicht erf¸llt");
  else if(!result && (result_tty == "Fehler"|| result_sshd == "Fehler" || result_syslog == "Fehler" || result_nfs == "Fehler" || result_permsecuretty == "Fehler" || result_permsshdconfig == "Fehler" || result_permlogindefs == "Fehler")) result = string("Fehler");
  else if (!result && result_tty == "ok" && result_sshd == "ok" && result_syslog == "ok" && result_nfs == "ok" && result_permsecuretty == "ok" && result_permsshdconfig == "ok" && result_permlogindefs == "ok")result = string("erf¸llt");
#################
}

if (!result){
      result = string("Fehler");
      desc = string('Beim Testen des Systems trat ein unbekannter Fehler auf bzw. es konnte kein Ergebnis ermittelt werden.'); 
}

set_kb_item(name:"GSHB-10/M4_021/result", value:result);
set_kb_item(name:"GSHB-10/M4_021/desc", value:desc);
set_kb_item(name:"GSHB-10/M4_021/name", value:name);

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

