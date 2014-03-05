###############################################################################
# OpenVAS Vulnerability Test
# $Id:
#
# List Files with setuid-bit in / and /home, Check /tmp for sticky-bit
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
tag_summary = "This plugin uses ssh to List Files with setuid-bit in / and /home, Check /tmp for sticky-bit.";

if(description)
{
  script_id(96069);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("List Files with setuid-bit in / and /home, Check /tmp for sticky-bit");

  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("List Files with setuid-bit in / and /home, Check /tmp for sticky-bit");
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
    set_kb_item(name: "GSHB/tempsticky", value:"error");
    set_kb_item(name: "GSHB/setuid/home", value:"error");
    set_kb_item(name: "GSHB/setuid/root", value:"error");
    set_kb_item(name: "GSHB/setuid/log", value:error);
    exit(0);
}

tempsticky = ssh_cmd(socket:sock, cmd:"ls -ld /tmp");
if ("ls: " >< tempsticky) tempsticky = "notmp";
else{
  val = split(tempsticky, sep:" ",keep:0);
  if ("t" >!< val[0])tempsticky = "false";
  else tempsticky = "true";
} 

homesetuid = ssh_cmd(socket:sock, cmd:"find /home -perm +4000 -type f");
rootsetuid = ssh_cmd(socket:sock, cmd:"find / -perm +4000 -type f");

if ("FIND: Invalid switch" >< homesetuid|| "FIND: Parameterformat falsch" >< homesetuid){
  set_kb_item(name: "GSHB/tempsticky", value:"windows");
  set_kb_item(name: "GSHB/setuid/home", value:"windows");
  set_kb_item(name: "GSHB/setuid/root", value:"windows");
  exit(0);
}

if (!homesetuid)homesetuid = "none";
if ("FIND:" >< homesetuid || "find:" >< homesetuid)homesetuid = "none";
if (!rootsetuid)rootsetuid = "none";
if ("FIND:" >< rootsetuid || "find:" >< rootsetuid)rootsetuid = "none";

set_kb_item(name: "GSHB/tempsticky", value:tempsticky);
set_kb_item(name: "GSHB/setuid/home", value:homesetuid);
set_kb_item(name: "GSHB/setuid/root", value:rootsetuid);
exit(0);
