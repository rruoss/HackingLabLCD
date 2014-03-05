###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_proftpd_server_remote_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# ProFTPD Server Remote Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Updated to include detect mechanism for single charecter after version
#  - By Antu Sanadi <santu@secpod.com> On 2009/11/1
#
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_summary = "This script detects the installed version of ProFTP Server
  and sets the version in KB.";

if(description)
{
  script_id(900815);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-08-14 14:09:35 +0200 (Fri, 14 Aug 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("ProFTPD Server Remote Version Detection");
  desc = "

  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the Version of ProFTPD Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("FTP");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/ftp", 21);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("ftp_func.inc");

## Constant Values
SCRIPT_OID ="1.3.6.1.4.1.25623.1.0.900815";
SCRIPT_DESC="ProFTPD Server Remote Version Detection";

ftpPort = get_kb_item("Services/ftp");
if(!ftpPort){
  ftpPort = 21;
}

if(!get_port_state(ftpPort)){
  exit(0);
}

# Get the version from banner
banner = get_ftp_banner(port:ftpPort);

if(banner != NULL)
{
  if("ProFTPD" >< banner)
  {
    set_kb_item(name:"ProFTPD/Intalled", value:TRUE);

    ftpVer = eregmatch(pattern:"ProFTPD ([0-9.]+)([A-Za-z0-9]+)?", string:banner);
    if(ftpVer[1] != NULL)
    {
      if(ftpVer[2] != NULL)
        ftpVer = ftpVer[1] + "." + ftpVer[2];
      else
        ftpVer = ftpVer[1];

      # Set KB for ProFTPD Version
      if(ftpVer != NULL){
        set_kb_item(name:"ProFTPD/Ver", value:ftpVer);
        security_note(data:"ProFTPD version " + ftpVer +
                           " was detected on the host");

         ## build cpe and store it as host_detail
         cpe = build_cpe(value: ftpVer, exp:"^([0-9.]+)(rc[0-9]+)?",base:"cpe:/a:proftpd:proftpd:");
         if(!isnull(cpe))
            register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

      }
    }
  }
}
