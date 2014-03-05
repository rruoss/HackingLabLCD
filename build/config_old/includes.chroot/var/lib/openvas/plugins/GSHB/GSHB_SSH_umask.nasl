###############################################################################
# OpenVAS Vulnerability Test
# $Id:
#
# List an Verify umask entrys in /etc/profile and ~/.profile
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
tag_summary = "This plugin uses ssh to List an Verify umask entrys in /etc/profile and ~/.profile.";

if(description)
{
  script_id(96068);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("List an Verify umask entrys in /etc/profile and ~/.profile");

  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("List an Verify umask entrys in /etc/profile and ~/.profile");
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
    set_kb_item(name: "GSHB/umask", value:"error");
    set_kb_item(name: "GSHB/umask/log", value:error);
    exit(0);
}

etcprofile = ssh_cmd(socket:sock, cmd:"cat /etc/profile");
if (!etcprofile){
    set_kb_item(name: "GSHB/umask", value:"error");
    set_kb_item(name: "GSHB/umask/log", value:"/etc/profile was not found");
    exit(0);
}

etcprofileumask = egrep(string:etcprofile, pattern:"umask [0-7]{3,4}");
if (etcprofileumask !~ "(u|U)(M|m)(A|a)(S|s)(K|k) 0027" && etcprofileumask !~ "(u|U)(M|m)(A|a)(S|s)(K|k) 0077") etcbit = "fail";
else etcbit = "pass";

UsProfLst = ssh_cmd(socket:sock, cmd:"locate /home/*/.profile");
if("command not found" >< UsProfLst) UsProfLst = ssh_cmd(socket:sock, cmd:"find /home -name .profile -type f -print");

if ("FIND: Invalid switch" >< UsProfLst|| "FIND: Parameterformat falsch" >< UsProfLst){
  set_kb_item(name: "GSHB/umask", value:"windows");
  exit(0);
}


if(UsProfLst) {
  spList = split(UsProfLst, keep:0);
  for(i=0; i<max_index(spList); i++){
    usrname = split(spList[i], sep:"/", keep:0);
    a = max_index(usrname) - 2;
    usrname = usrname[a];
    usrprofile = ssh_cmd(socket:sock, cmd:"cat " + spList[i]);
    usrprofileumask = egrep(string:usrprofile, pattern:"umask [0-7]{3,4}");
    if ("#" >!< usrprofileumask){
          if (usrprofileumask !~ "(u|U)(M|m)(A|a)(S|s)(K|k) 0027" && usrprofileumask !~ "(u|U)(M|m)(A|a)(S|s)(K|k) 0077") failuser += "User: " + usrname + ", File: "+ spList[i] + "=" + usrprofileumask;
    }else usrbit = "noconf";
  }
}else usrbit = "noconf";

if (etcbit == "fail" && usrbit == "noconf") umaskfail = "1";
if (etcbit == "pass" && failuser) umaskfail = "1";
if (umaskfail = "1"){
  if (etcbit == "pass" && failuser) result = failuser;
  else if (etcbit == "fail" && usrbit == "noconf" && failuser) result = "/etc/profile = " + etcprofileumask + failuser;
  else result = "/etc/profile=" + etcprofileumask;
}else result = "none";

set_kb_item(name: "GSHB/umask", value:result);
exit(0);
