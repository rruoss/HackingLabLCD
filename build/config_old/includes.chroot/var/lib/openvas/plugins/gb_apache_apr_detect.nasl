##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_apr_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# Apache APR Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_summary = "This script detects the installed version of Apache APR
  and sets the result in KB.";

if(description)
{
  script_id(800680);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-08-17 14:35:19 +0200 (Mon, 17 Aug 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Apache APR Version Detection");
  desc = "

  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set Version of Apache APR in KB");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800680";
SCRIPT_DESC = "Apache APR Version Detection";

apr_sock = ssh_login_or_reuse_connection();
if(!apr_sock){
  exit(0);
}

foreach path (make_list("apr-config" ,"apr-1-config"))
{
  getPath = find_bin(prog_name:path, sock:apr_sock);

  foreach binaryFile (getPath)
  {
    aprVer = get_bin_version(full_prog_name:chomp(binaryFile), sock:apr_sock,
                             version_argv:"--version", ver_pattern:"[0-9.]+");

    if(aprVer[0] != NULL)
    {
      set_kb_item(name:"Apache/APR/Ver", value:aprVer[0]);
      security_note(data:"Apache APR version " + aprVer[0] + " running at location "
                         + binaryFile +  " was detected on the host");

      ## build cpe and store it as host_detail
      cpe = build_cpe(value:aprVer[0], exp:"^([0-9.]+)", base:"cpe:/a:apache:portable_runtime:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
  }
}
ssh_close_connection();
