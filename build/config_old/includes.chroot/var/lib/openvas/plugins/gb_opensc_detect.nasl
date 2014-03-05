###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opensc_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# OpenSC Version Detection
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
tag_summary = "This script detects the version of OpenSC and sets the
  result in the KB.";

if(description)
{
  script_id(800369);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-16 10:38:04 +0100 (Mon, 16 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("OpenSC Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the version of OpenSC");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800369";
SCRIPT_DESC = "OpenSC Version Detection";

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

# Set KB for OpenSC
openscName = find_file(file_name:"opensc-config", file_path:"/",
                       useregex:TRUE, regexpar:"$", sock:sock);
if(openscName != NULL)
{
  foreach binName (openscName)
  {
    binName = chomp(binName);
    openscVer = get_bin_version(full_prog_name:binName, ver_pattern:"([0-9.]+)",
                                version_argv:"--version", sock:sock);
    if(openscVer[0] != NULL)
    {
      set_kb_item(name:"OpenSC/Ver", value:openscVer[0]);
      security_note(data:"OpenSC version " + openscVer[0] + " running at location " 
                          + binName + " was detected on the host");
      ssh_close_connection();
   
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:openscVer[0], exp:"^([0-9.]+)", base:"cpe:/a:opensc-project:opensc:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

      exit(0);
    }
  }
}
ssh_close_connection();
