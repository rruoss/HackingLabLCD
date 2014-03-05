###############################################################################
# OpenVAS Vulnerability Test
# $Id:
#
# Read the Screensaver-Configuration (enabled and lock) on GNOME and KDE
#
# Authors:
# Thomas Rotter <T.Rotter@dn-systems.de>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
#
#
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
tag_summary = "Read the Screensaver-Configuration (enabled and lock) on GNOME and KDE.";

if(description)
{
  script_id(96089);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Wed Jun 23 14:20:09 2010 +0200");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Read the Screensaver-Configuration (enabled and lock) on GNOME and KDE");

  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("Read the Screensaver-Configuration (enabled and lock) on GNOME and KDE");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_dependencies("find_service.nasl", "ssh_authorization.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

cmdline = 0;
include("ssh_func.inc");

port = get_preference("auth_port_ssh");
if(!port) port = get_kb_item("Services/ssh");
if(!port) {
    port = 22;
}
sock = ssh_login_or_reuse_connection();
if(!sock) {
    error = get_ssh_error();
    if (!error) error = "No SSH Port or Connection!";
    log_message(port:port, data:error);
    set_kb_item(name: "GSHB/gnomescreensaver", value:"error");
    set_kb_item(name: "GSHB/screensaverdaemon", value:"error");
    set_kb_item(name: "GSHB/defkdescreensav", value:"error");
    set_kb_item(name: "GSHB/userkdescreensav", value:"error");
    set_kb_item(name: "GSHB/gnomescreensaver/log", value:error);
    exit(0);
}

gnomescreensaver = ssh_cmd(socket:sock, cmd:"LANG=C gconftool-2 -a /apps/gnome-screensaver");
screensaverdaemon = ssh_cmd(socket:sock, cmd:"LANG=C gconftool-2 -a /apps/gnome_settings_daemon/screensaver");

lstkdescreensav = ssh_cmd(socket:sock, cmd:"LANG=C find /home/ -name kscreensaverrc");
defkdescreensav = ssh_cmd(socket:sock, cmd:"LANG=C cat /etc/kde4/share/config/kscreensaverrc");

if ("FIND: Invalid switch" >< lstkdescreensav|| "FIND: Parameterformat falsch" >< lstkdescreensav){
  set_kb_item(name: "GSHB/gnomescreensaver", value:"windows");
  set_kb_item(name: "GSHB/screensaverdaemon", value:"windows");
  set_kb_item(name: "GSHB/defkdescreensav", value:"windows");
  set_kb_item(name: "GSHB/userkdescreensav", value:"windows");
  exit(0);
}

if (defkdescreensav =~ ".*cannot open /etc/kde4/share/config/kscreensaverrc.*" ||  defkdescreensav =~ ".*No such file or directory.*") defkdescreensav = "none";
  
if (!gnomescreensaver) gnomescreensaver = "none";
#if (!screensaverdaemon) screensaverdaemon = "none";
if (!lstkdescreensav) lstkdescreensav = "none";
if (!defkdescreensav) defkdescreensav = "none";

if (gnomescreensaver != "none"){
  if ("start_screensaver = true" >< screensaverdaemon)screensaverdaemon = "true";
  else if (!screensaverdaemon) screensaverdaemon = "none";
  else screensaverdaemon = "false";
  val1 ="";
  val2 ="";
  Lst = split(gnomescreensaver, keep:0);
  for(i=0; i<max_index(Lst); i++){
    if (Lst[i] == " lock_enabled = true") val1 = "true";
    if (Lst[i] == " idle_activation_enabled = true") val2 = "true";
  }
  if (val1 == "true" && val2 == "true") gnomescreensaver = "true";
  else gnomescreensaver = "false";
}
else if (defkdescreensav != "none"){
  val1 ="";
  val2 ="";
  Lst = split(defkdescreensav, keep:0);
  for(i=0; i<max_index(Lst); i++){
    if (Lst[i] == "Enabled=true") val1 = "true";
    if (Lst[i] == "Lock=true") val2 = "true";
  }
  if (val1 == "true" && val2 == "true") defkdescreensav = "true";
  else defkdescreensav = "false";
   
  
  if (lstkdescreensav != "none"){
    lstLst = split(lstkdescreensav, keep:0);
    if (max_index(lstLst) > 1){
      for(i=0; i<max_index(lstLst); i++){
        val1 ="";
        val2 ="";
        val3 = ssh_cmd(socket:sock, cmd:"cat " + lstLst[i]);
        Lst = split(val3, keep:0);
        for(i=0; i<max_index(Lst); i++){
          if (Lst[i] == "Enabled=false") val1 = "false";
          else if (Lst[i] == "Enabled=true") val1 = "true";
          if (Lst[i] == "Lock=true") val2 = "true";
        }
        if ((val1 != "false" || val1 == "true") && val2 == "true") valtmp += "true";
        else valtmp += "false";
      }
      if ("false" >< valtmp)lstkdescreensav = "false";
      else lstkdescreensav = "true";
    }else{
      val1 ="";
      val2 ="";
      val3 = ssh_cmd(socket:sock, cmd:"cat " + lstkdescreensav);
      Lst = split(val3, keep:0);
      for(i=0; i<max_index(Lst); i++){
        if (Lst[i] == "Enabled=false") val1 = "false";
        else if (Lst[i] == "Enabled=true") val1 = "true";
        if (Lst[i] == "Lock=true") val2 = "true";
      }
      if ((val1 != "false" || val1 == "true") && val2 == "true") lstkdescreensav = "true";
      else lstkdescreensav = "false";
    }
  }
}

if (!screensaverdaemon) screensaverdaemon = "none";

set_kb_item(name: "GSHB/gnomescreensaver", value:gnomescreensaver);
set_kb_item(name: "GSHB/screensaverdaemon", value:screensaverdaemon);
set_kb_item(name: "GSHB/defkdescreensav", value:defkdescreensav);
set_kb_item(name: "GSHB/userkdescreensav", value:lstkdescreensav);
exit(0);
