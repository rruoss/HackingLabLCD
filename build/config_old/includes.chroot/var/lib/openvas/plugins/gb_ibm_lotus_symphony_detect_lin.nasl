###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_lotus_symphony_detect_lin.nasl 44 2013-11-04 19:58:48Z jan $
#
# IBM Lotus Symphony Version Detection (Linux)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "This script finds the installed IBM Lotus Symphony version and
  saves the result in KB.";

if(description)
{
  script_id(802230);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 44 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2011-08-05 09:04:20 +0200 (Fri, 05 Aug 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("IBM Lotus Symphony Version Detection (Linux)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set the version of IBM Lotus Symphony in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Service detection");
  script_mandatory_keys("login/SSH/success");
  script_dependencies("ssh_authorization.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");

## Connecting...
sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

## Confirm Linux, as SSH can be installed on Windows as well
result = ssh_cmd(socket:sock, cmd:"uname");
if("Linux" >!< result){
  exit(0);
}

## Read "about.mappings" File
cmd = "find / -name about.mappings -type f";
paths = split(ssh_cmd(socket:sock, cmd: cmd, timeout:60));
if(paths != NULL)
{
  foreach path (paths)
  {
    ## Confirm Symphony Path
    if("com.ibm.symphony" >< path) {
      file = ssh_cmd(socket:sock, cmd: "cat " + path);
    }
  }
}

ssh_close_connection();

## Confirm Symphony File
if(isnull(file) || "Symphony" >!< file){
  exit(0);
}

## Get Version
foreach line(split(file))
{
  version = eregmatch(pattern:"1=([0-9.]+).?([a-zA-Z0-9]+)?", string:line);
  if(version[1] != NULL)
  {
    symVer = version[1];
    if(version[2] != NULL) {
      symVer = version[1] + "." + version[2];
    }
    break;
  }
}

if(symVer)
{
  ## Set Symphony Version in KB
  set_kb_item(name:"IBM/Lotus/Symphony/Lin/Ver", value:symVer);
  security_note(data:"IBM Lotus Symphony version " + symVer +
                     " was detected on the host");
}
