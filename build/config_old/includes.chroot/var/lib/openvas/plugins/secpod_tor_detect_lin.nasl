###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_tor_detect_lin.nasl 42 2013-11-04 19:41:32Z jan $
#
# Tor Version Detection (Linux)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) SecPod http://www.secpod.com
#
# Script Modified by Sharath S <sharaths@secpod.com> On 14th July 2009
# NOTE: Patterns and variables used previously were wrong.
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
tag_summary = "This script is detects the installed version of Tor and
  sets the result in KB.";

if(description)
{
  script_id(900418);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 42 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:41:32 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2008-12-31 15:14:17 +0100 (Wed, 31 Dec 2008)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Tor Version Detection (Linux)");
  desc = "

  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Check for Tor version");
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

include("cpe.inc");
include("host_details.inc");
include("ssh_func.inc");
include("version_func.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900418";
SCRIPT_DESC = "Tor Version Detection (Linux)";

tor_sock = ssh_login_or_reuse_connection();
if(!tor_sock){
  exit(0);
}

torName = find_file(file_name:"tor", file_path:"/", useregex:TRUE,
                    regexpar:"$", sock:tor_sock);

foreach binaryName (torName)
{
  binaryName = chomp(binaryName);
  torVer = get_bin_version(full_prog_name:binaryName, sock:tor_sock,
                           version_argv:"--version",
                           ver_pattern:"Tor v([0-9.]+-?([a-z0-9]+)?)");
  if(torVer[1] != NULL)
  {
    set_kb_item(name:"Tor/Linux/Ver", value:torVer[1]);
    security_note(data:"Tor version " + torVer[1] + " running at location "
                       + binaryName + " was detected on the host");
    ssh_close_connection();

    ## build cpe and store it as host_detail
    cpe = build_cpe(value: torVer[1], exp:"^([0-9.]+-?([a-z0-9]+)?)",base:"cpe:/a:tor:tor:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

  }
}
ssh_close_connection();
