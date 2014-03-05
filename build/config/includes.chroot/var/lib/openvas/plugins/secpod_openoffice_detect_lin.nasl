###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_openoffice_detect_lin.nasl 15 2013-10-27 12:49:54Z jan $
#
# OpenOffice Version Detection (Linux)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.org
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
tag_summary = "The script detects the version of OpenOffice and sets the
  result in KB.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900073";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-01-29 15:16:47 +0100 (Thu, 29 Jan 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("OpenOffice Version Detection (Linux)");
  desc = "

  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set the KB for the version of OpenOffice");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
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
SCRIPT_DESC = "OpenOffice Version Detection (Linux)";

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

openName = find_file(file_name:"versionrc", file_path:"/", useregex:TRUE,
                    regexpar:"$", sock:sock);
foreach binaryName (openName)
{
  binaryName = chomp(binaryName);
  if("openoffice" >!< binaryName){
    continue;
  }

  openVer = get_bin_version(full_prog_name:"cat", version_argv:binaryName,
                           ver_pattern:"[0-9]\.[0-9](\.[0-9])?", sock:sock);
  if(openVer[0] != NULL)
  {
    set_kb_item(name:"OpenOffice/Linux/Ver", value:openVer[0]);
    ssh_close_connection();
   
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:openVer[0], exp:"^([0-9.]+)", base:"cpe:/a:openoffice:openoffice.org:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    log_message(data:'Detected OpenOffice version: ' + openVer[0] +
                '\nLocation: ' + binaryName +
                '\n\nConcluded from version identification result:\n' +
                 openVer[max_index(openVer)-1]);

    exit(0);
  }
}
ssh_close_connection();
