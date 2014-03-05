###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_realplayer_detect_lin.nasl 14 2013-10-27 12:33:37Z jan $
#
# RealPlayer Version Detection (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_summary = "This script detects the installed version of RealPlayer and sets
  the reuslt in KB.";

if(description)
{
  script_id(902106);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-02-02 07:26:26 +0100 (Tue, 02 Feb 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("RealPlayer Version Detection (Linux)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the version of RealPlayer");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
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

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

rpbin = find_bin(prog_name:"realplay", sock:sock);
if(isnull(rpbin)){
  exit(0);
}

foreach dir(make_list("/opt/real/RealPlayer", "/usr/local/RealPlayer"))
{
  paths = find_file(file_name:"README",file_path: dir, useregex:TRUE,
                    regexpar:"$", sock:sock);
  foreach binName (paths)
  {
    rpVer = get_bin_version(full_prog_name:"cat", version_argv:binName,
                                ver_pattern:"RealPlayer ([0-9.]+)",
                                sock:sock);
    if(rpVer[1] != NULL)
    {
      set_kb_item(name:"RealPlayer/Linux/Ver", value:rpVer[1]);
      security_note(data:"RealPlayer version " + rpVer[1] + " running at " +
                         "location " + binName +  " was detected on the host");
      exit(0);
    }
  }
}
ssh_close_connection();
