###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_detect_lin.nasl 15 2013-10-27 12:49:54Z jan $
#
# Mozilla Version Detection (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "This script is detects the installed version of Mozilla Browser
  and sets the result in KB.";

if(description)
{
  script_id(800884);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-09-07 19:45:38 +0200 (Mon, 07 Sep 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Mozilla Version Detection (Linux)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the version of Mozilla Browser");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800884";
SCRIPT_DESC = "Mozilla Version Detection (Linux)";

mozilla_sock = ssh_login_or_reuse_connection();
if(!mozilla_sock){
  exit(0);
}

mozillaName = find_file(file_name:"mozilla", file_path:"/", useregex:TRUE,
                    regexpar:"$", sock:mozilla_sock);

foreach binary_name (mozillaName)
{
  binary_name = chomp(binary_name);
  mozillaVer = get_bin_version(full_prog_name:binary_name, sock:mozilla_sock,
                               version_argv:"-v", ver_pattern:"Mozilla " +
                               "([0-9]\.[0-9.]+)(.*build ([0-9]+))?");
  if(!isnull(mozillaVer[1]))
  {
    set_kb_item(name:"Mozilla/Linux/Ver", value:mozillaVer[1]);
    if(!isnull(mozillaVer[3]))
    {
      ver = mozillaVer[1] + "." + mozillaVer[3];
      set_kb_item(name:"Mozilla/Build/Linux/Ver", value:ver);
      security_note(data:"Mozilla version " + ver + " running at location " + 
                        binary_name + " was detected on the host");
  
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:ver, exp:"^([0-9.]+)", base:"cpe:/a:mozilla:mozilla:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
  }
}
ssh_close_connection();
