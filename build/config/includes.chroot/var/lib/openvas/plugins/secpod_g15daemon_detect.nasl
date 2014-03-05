###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_g15daemon_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# G15Daemon Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_summary = "This script detects the installed version of G15Daemon and
  sets the reuslt in KB.";

if(description)
{
  script_id(900853);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-09-18 08:01:03 +0200 (Fri, 18 Sep 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("G15Daemon Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the version of G15Daemon");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
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
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900853";
SCRIPT_DESC = "G15Daemon Version Detection";

g15d_sock = ssh_login_or_reuse_connection();
if(!g15d_sock) {
  exit(0);
}

g15dName = find_bin(prog_name:"g15daemon", sock:g15d_sock);
foreach binName (g15dName)
{
  g15dVer = get_bin_version(full_prog_name:chomp(binName), sock:g15d_sock,
            version_argv:"-version", ver_pattern:"G15Daemon" +
                         " version ([0-9]\.[0-9.]+([a-z]+)?)");
  if(g15dVer[1] != NULL){
    set_kb_item(name:"G15Daemon/Ver", value:g15dVer[1]);
    security_note(data:"G15Daemon version " + g15dVer[1] +
             " running at location " + binName + " was detected on the host");
    
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:g15dVer[1], exp:"^([0-9.]+)", base:"cpe:/a:g15tools:g15daemon:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

  }
}
ssh_close_connection();
