###############################################################################
# OpenVAS Vulnerability Test
# $Id:
#
# Check write permissions of system-directorys
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
tag_summary = "This plugin uses ssh to Check write permissions of system-directorys.";

if(description)
{
  script_id(96081);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2010-06-02 09:25:45 +0200 (Wed, 02 Jun 2010)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Check write permissions of system-directorys");

  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("Check write permissions of system-directorys");
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
    set_kb_item(name: "GSHB/Dir-Writeperm", value:"error");
    set_kb_item(name: "GSHB/Dir-Writeperm/log", value:error);
    exit(0);
}

writeperm = ssh_cmd(socket:sock, cmd:"find / -mount -type d -perm -002");

if (!writeperm) writeperm = "none";
else if(writeperm != "none"){
  Lst = split(writeperm,keep:0);
  if (Lst){
    for (i=0; i<max_index(Lst); i++){
      if ("/home/" >< Lst[i] || "/tmp" >< Lst[i] || "Keine Berechtigung" >< Lst[i] || "Permission denied" >< Lst[i]) continue;
      ClearLst +=  Lst[i] + '\n';
    }
  }else if ("/home/" >!< Lst[i] && "/tmp" >!< Lst[i] && "Keine Berechtigung" >!< Lst[i] && "Permission denied" >!< Lst[i]) Clearlist = writeperm;
}  

if ("FIND: Invalid switch" >< ClearLst|| "FIND: Parameterformat falsch" >< ClearLst) ClearLst = "windows";
else if (ClearLst =~ "(F|f)(I|i)(N|n)(D|d): .*") ClearLst = "nofind";
else if (!ClearLst) ClearLst = "none";

set_kb_item(name: "GSHB/Dir-Writeperm", value:ClearLst);

exit(0);
