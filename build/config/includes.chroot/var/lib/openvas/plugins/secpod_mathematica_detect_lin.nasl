###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mathematica_detect_lin.nasl 14 2013-10-27 12:33:37Z jan $
#
# Mathematica Version Detection (Linux)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_summary = "This script finds the installed Mathematica version and saves the
  result in KB.";

if(description)
{
  script_id(901118);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-06-01 15:40:11 +0200 (Tue, 01 Jun 2010)");
  script_name("Mathematica Version Detection (Linux)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set the version of Mathematica in KB");
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
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.901118";
SCRIPT_DESC = "Mathematica Version Detection (Linux)";

## Create Socket
sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

## Confirm Linux, as SSH can be instslled on Windows as well
result = ssh_cmd(socket:sock, cmd:"uname");
if("Linux" >!< result){
  exit(0);
}

## Get Mathematica Path
paths = find_file(file_name:".VersionID", file_path:"/",
                  useregex:TRUE, regexpar:"$", sock:sock);

if(paths != NULL)
{
  foreach path (paths)
  {
    ## Check path is having "Mathematica" in it
    if("Mathematica" >< path)
    {
      ## Read Mathematica Version From .VersionID File
      mPath = ereg_replace(pattern:" ", replace:"\ ", string:path);
      mVer = get_bin_version(full_prog_name:"cat", version_argv:mPath,
                             ver_pattern:"([0-9.]+)", sock:sock);
      if(mVer[1] != NULL)
      {
        ## Set Mathematica Version in KB
        set_kb_item(name:"Mathematica/Ver", value:mVer[1]);
        security_note(data:"Mathematica version " + mVer[1] +
                           " running at location " + path +
                           " was detected on the host");
      
        ## build cpe and store it as host_detail
        cpe = build_cpe(value:mVer[1], exp:"^([0-9.]+)", base:"cpe:/a:wolfram_research:mathematica:");
        if(!isnull(cpe))
           register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

      }
    }
  }
}
ssh_close_connection();
