###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_xnview_detect_lin.nasl 14 2013-10-27 12:33:37Z jan $
#
# XnView Version Detection (Linux)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_summary = "This script detects the installed version of XnView and
  sets the result in KB.";

if(description)
{
  script_id(900753);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-03-30 16:15:33 +0200 (Tue, 30 Mar 2010)");
  script_name("XnView Version Detection (Linux)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  desc = "
  Summary:
  " + tag_summary;  script_description(desc);
  script_summary("Set KB for the version of XnView");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Service detection");
  script_dependencies("find_service.nasl","ssh_authorization.nasl");
  script_mandatory_keys("login/SSH/success");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900753";
SCRIPT_DESC = "XnView Version Detection (Linux)";

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

## Get Bin Path
paths = find_bin(prog_name:"xnview", sock:sock);
foreach xnviewbin (paths)
{
  xnviewVer = get_bin_version(full_prog_name:chomp(xnviewbin), sock:sock,
                              version_argv:"-help",
                              ver_pattern:"XnView v([0-9.]+)");
  if(xnviewVer[1] != NULL){
    set_kb_item(name:"XnView/Linux/Ver", value:xnviewVer[1]);
    security_note(data:"XnView version " + xnviewVer[1] + " running at " +
                       "location " + xnviewbin + " was detected on the host");
      
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:xnviewVer[1], exp:"^([0-9.]+)", base:"cpe:/a:xnview:xnview:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    exit(0);
  }
}
ssh_close_connection();
