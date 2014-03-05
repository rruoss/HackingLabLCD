###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_seamonkey_detect_lin.nasl 42 2013-11-04 19:41:32Z jan $
#
# Mozilla Seamonkey Version Detection (Linux)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "This script finds the Mozilla SeaMonkey installed version on
  Linux and saves the version in KB.";


if(description)
{
  script_id(800019);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 42 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:41:32 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2008-10-07 14:21:23 +0200 (Tue, 07 Oct 2008)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Mozilla SeaMonkey Version Detection (Linux)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_family("General");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_summary("Set File Version of Mozilla SeaMonkey in KB");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800019";
SCRIPT_DESC = "Mozilla SeaMonkey Version Detection (Linux)";

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

seaName = find_file(file_name:"seamonkey", file_path:"/", useregex:TRUE,
                    regexpar:"$", sock:sock);
if(!seaName){
  seaName = find_file(file_name:"iceape", file_path:"/", useregex:TRUE,
                      regexpar:"$", sock:sock);
}
foreach binary_seaName (seaName)
{
  binary_name = chomp(binary_seaName);
  seaVer = get_bin_version(full_prog_name:binary_name, version_argv:"-v",
                           ver_pattern:"[0-9].[0-9.]+");
  if(seaVer)
  {
    set_kb_item(name:"Seamonkey/Linux/Ver", value:seaVer[0]);
    security_note(data:"Mozilla Seamonkey version " + seaVer[0] + 
                  " running at location " + binary_seaName + " was detected on the host");
    ssh_close_connection();
   
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:seaVer[0], exp:"^([0-9.]+([a-z0-9]+)?)", base:"cpe:/a:mozilla:seamonkey:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    exit(0);
  }
}
ssh_close_connection();