###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_firefox_detect_lin.nasl 42 2013-11-04 19:41:32Z jan $
#
# Mozilla Firefox Version Detection (Linux)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# Modified to Detect All Installed Version
#  - By Sharath S <sharaths@secpod.com> on 2009-09-04 #4411
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
tag_summary = "This script finds the Mozilla Firefox installed version on Linux
  and save the version in KB.";


if(description)
{
  script_id(800017);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 42 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:41:32 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2008-10-07 14:21:23 +0200 (Tue, 07 Oct 2008)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Mozilla Firefox Version Detection (Linux)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_family("Service detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_summary("Set file version of Mozilla Firefox in KB");
  script_mandatory_keys("login/SSH/success");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800017";
SCRIPT_DESC = "Mozilla Firefox Version Detection (Linux)";

fox_sock = ssh_login_or_reuse_connection();
if(!fox_sock)
{
  exit(0);
}

foxName = find_file(file_name:"firefox", file_path:"/", useregex:TRUE,
                    regexpar:"$", sock:fox_sock);

foreach binary_foxName (foxName)
{
  binary_name = chomp(binary_foxName);
  foxVer = get_bin_version(full_prog_name:binary_name, sock:fox_sock,
                           version_argv:"-v", ver_pattern:"Mozilla Firefox " +
                           "([0-9]\.[0-9.]+([a-z0-9]+)?)");
  if(!isnull(foxVer[1]))
  {
    set_kb_item(name:"Firefox/Linux/Ver", value:foxVer[1]);
    security_note(data:"Firefox Browser version " + foxVer[1] + " running at" + 
                       " location " + binary_foxName +  " was detected on the host");
    
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:foxVer[1], exp:"^([0-9.a-z]+)", base:"cpe:/a:mozilla:firefox:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

  }
}
ssh_close_connection();
