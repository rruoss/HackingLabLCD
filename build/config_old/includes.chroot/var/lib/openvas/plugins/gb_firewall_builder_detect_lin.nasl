###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_firewall_builder_detect_lin.nasl 14 2013-10-27 12:33:37Z jan $
#
# Firewall Builder Version Detection (Linux)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_summary = "This script detects the installed version of Firewall Builder
  and sets the result in KB.";

if(description)
{
  script_id(800995);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-03-18 15:44:57 +0100 (Thu, 18 Mar 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Firewall Builder Version Detection (Linux)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set version of Firewall Builder in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800995";
SCRIPT_DESC = "Firewall Builder Version Detection (Linux)";

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

paths = find_bin(prog_name:"fwbuilder", sock:sock);
foreach fwbuildbin (paths)
{
  fwbuildVer = get_bin_version(full_prog_name:chomp(fwbuildbin), sock:sock,
                              version_argv:"-v", ver_pattern:"([0-9.]+)");
  if(fwbuildVer[1] != NULL)
   {
     set_kb_item(name:"FirewallBuilder/Linux/Ver", value:fwbuildVer[1]);
     security_note(data:"Firewall Builder version " + fwbuildVer[1] + " running" + 
                        " at location " + fwbuildbin + " was detected on the host");
      
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:fwbuildVer[1], exp:"^([0-9.]+)", base:"cpe:/a:fwbuilder:firewall_builder:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

  }
}
ssh_close_connection();
