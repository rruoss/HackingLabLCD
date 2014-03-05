###############################################################################
# Openvas Vulnerability Test
# $id: gb_visualization_library_detect_lin.nasl 7616 2010-03-11 15:50:35z mar $
#
# Description: Visualization Library Version Detection (Linux)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the gnu general public license version 2
# (or any later version), as published by the free software foundation.
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
tag_summary = "This script detects the installed version of Visualization
  Library and sets the result in KB.";

if(description)
{
  script_id(800997);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-03-18 15:44:57 +0100 (Thu, 18 Mar 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Visualization Library Version Detection (Linux)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set version of Visualization Library in KB");
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

## Open SSH Login connection
sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

## Check for the file version.hpp
paths = find_file(file_name:"version.hpp", file_path: "/usr/", useregex:TRUE,
                    regexpar:"$", sock:sock);
if(paths == NULL){
  exit(0);
}

## Check for /vl/ path
if(paths =~ "/vl/" )
{
  foreach binName (paths)
  {
    ## Get file contents
    rpVer = get_bin_version(full_prog_name:"cat", version_argv:binName,
                                ver_pattern:" ", sock:sock);
    ## Extract File Contents
    mjVer = eregmatch(pattern:"VL_Major ([0-9]+)",string:rpVer[1], icase:1);
    mnVer = eregmatch(pattern:"VL_Minor ([0-9]+)",string:rpVer[1], icase:1);
    blVer = eregmatch(pattern:"VL_Build ([0-9]+)",string:rpVer[1], icase:1);

    if(mnVer[1] != NULL)
    {
      ## Construct File Version
      vlVer = mjVer[1] + "." + mnVer[1] + "." + blVer[1];
      if(vlVer != NULL)
      {
        ## Set the version into the KB
        set_kb_item(name:"VisualizationLibrary/Linux/Ver", value:vlVer);
        security_note(data:"Visualization Library version " + vlVer + 
                        " was detected on the host");
        ssh_close_connection();
        exit(0);
      }
    }
  }
}
ssh_close_connection();
