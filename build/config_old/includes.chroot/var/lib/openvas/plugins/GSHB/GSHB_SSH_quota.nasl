###############################################################################
# OpenVAS Vulnerability Test
# $Id:
#
# Check if Disk Quota activated.
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
tag_summary = "This plugin uses ssh to Check if Disk Quota activated.";

if(description)
{
  script_id(96075);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Wed Apr 07 15:31:43 2010 +0200");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Check if Disk Quota activated.");

  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("Check if Disk Quota activated.");
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
    set_kb_item(name: "GSHB/quota/fstab", value:"error");
    set_kb_item(name: "GSHB/quota/user", value:"error");
    set_kb_item(name: "GSHB/quota/group", value:"error");
    set_kb_item(name: "GSHB/quota/log", value:error);
    exit(0);
}

windowstest = ssh_cmd(socket:sock, cmd:"cmd /?");
if (("windows" >< windowstest && "interpreter" >< windowstest) || ("Windows" >< windowstest && "interpreter" >< windowstest)){
    set_kb_item(name: "GSHB/quota/fstab", value:"windows");
    set_kb_item(name: "GSHB/quota/user", value:"windows");
    set_kb_item(name: "GSHB/quota/group", value:"windows");
  exit(0);
}

uname = ssh_cmd(socket:sock, cmd:"uname -rs");
uname = ereg_replace(pattern:'\n',replace:'', string:uname);
if (uname !~ "SunOS .*"){
  fstab = ssh_cmd(socket:sock, cmd:"grep -v '^ *#' /etc/fstab");
  aquotauser = ssh_cmd(socket:sock, cmd:"ls -lah /aquota.user");
  aquotagroup = ssh_cmd(socket:sock, cmd:"ls -lah /aquota.group");

  if ("grep: command not found" >< fstab) fstab = "nogrep";
  if ("ls: command not found" >< aquotauser) aquotauser = "nols";
  if ("ls: cannot access /aquota.user:" >< aquotauser || "ls: Zugriff auf /aquota.user" >< aquotauser) aquotauser = "none";
  if ("ls: command not found" >< aquotagroup) aquotagroup = "nols";
  if ("ls: cannot access /aquota.group:" >< aquotagroup || "ls: Zugriff auf /aquota.group" >< aquotagroup) aquotagroup = "none";
  if (fstab != "nogrep")fstabquota = egrep(string:fstab, pattern:"quota", icase:0);
  if (!fstabquota || fstabquota == " ") fstabquota = "none";
  set_kb_item(name: "GSHB/quota/fstab", value:fstabquota);
  set_kb_item(name: "GSHB/quota/user", value:aquotauser);
  set_kb_item(name: "GSHB/quota/group", value:aquotagroup);
  
}
else if(uname =~ "SunOS .*"){
  repquota = ssh_cmd(socket:sock, cmd:"LANG=C /usr/sbin/repquota -va");
  zfsgetquota = ssh_cmd(socket:sock, cmd:"LANG=C /usr/sbin/zfs get quota");
  
  if (repquota =~ ".*repquota: not found.*") ufsquota = "norepquota";
  else if (repquota =~ "^quotactl: no quotas file.*") ufsquota = "noquota";
  else ufsquota = repquota;
  
  if (zfsgetquota =~ ".*zfs: not found.*") zfsquota = "nozfs";
  else {
    Lst = split(zfsgetquota, keep:0);
    for(i=1; i<max_index(Lst); i++){
  
      if (Lst[i] =~ '^.*quota[ ]{5}(none|-).*')continue;
      else if (Lst[i] =~ '^.*quota.*')tmp = Lst[i];
      zfsquota += tmp + '\n';
    }
  }
  if (!zfsquota) zfsquota = "noquota";
  
  set_kb_item(name: "GSHB/quota/uname", value:uname);
  set_kb_item(name: "GSHB/quota/zfsquota", value:zfsquota);
  set_kb_item(name: "GSHB/quota/ufsquota", value:ufsquota);
}

exit(0);
