##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apache_apr-utils_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# Apache APR-Utils Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
#
# Updated to Detect Zero Series Versions
#  - By Antu Sanadi <santu@secpod.com> On 2009-08-14
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
tag_summary = "This script retrieves the version of Apache APR-Utils
  and saves the result in KB.";

if(description)
{
  script_id(900571);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-06-24 07:17:25 +0200 (Wed, 24 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Apache APR-Utils Version Detection");
  desc = "

  Summary:
  " + tag_summary;
  script_description(desc);
  script_family("Service detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_summary("Set Version of Apache APR-Utils in KB");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900571";
SCRIPT_DESC = "Apache APR-Utils Version Detection";

util_sock = ssh_login_or_reuse_connection();
if(!util_sock){
  exit(0);
}

foreach path (make_list("apu-config" ,"apu-1-config"))
{
  getPath = find_bin(prog_name:path, sock:util_sock);

  foreach binaryFile (getPath)
  {
    utilsVer = get_bin_version(full_prog_name:chomp(binaryFile), sock:util_sock,
                               version_argv:"--version", ver_pattern:"[0-9.]+");

    if(utilsVer[0] != NULL){
      set_kb_item(name:"Apache/APR-Utils/Ver", value:utilsVer[0]);
      security_note(data:"Apache APR-Utils version " + utilsVer[0] +
          " running at location " + binaryFile + " was detected on the host");

      ## build cpe and store it as host_detail
      cpe = build_cpe(value:utilsVer[0], exp:"^([0-9.]+)", base:"cpe:/a:apache:apr-util:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
  }
}
ssh_close_connection();
