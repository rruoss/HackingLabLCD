###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_proftpd_server_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# ProFTPD Server Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
#
# Modified Set KB for Local Check Only
#  - By Sharath S <sharaths@secpod.com> On 2009-08-14
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
tag_summary = "This script detects the installed version of ProFTP Server and
  saves the version in KB.";

if(description)
{
  script_id(900506);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-20 17:40:17 +0100 (Fri, 20 Feb 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("ProFTPD Server Version Detection");
  desc = "

  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the Version of ProFTPD Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("FTP");
  script_dependencies("secpod_proftpd_server_remote_detect.nasl");
  script_require_keys("ProFTPD/Intall");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("ssh_func.inc");
include("version_func.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900506";
SCRIPT_DESC = "ProFTPD Server Version Detection";

# Check for Version is Getting from Banner
if(get_kb_item("ProFTPD/Ver")  != NULL){
  exit(0);
}

# Grep the Version from File
sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

# Get the Installated Path
ftpPaths = find_file(file_name:"proftpd", file_path:"/", useregex:TRUE,
                     regexpar:"$", sock:sock);

foreach binPath (ftpPaths)
{
  # Grep the Version from File
  ftpVer = get_bin_version(full_prog_name:chomp(binPath), version_argv:"-v",
                         ver_pattern:"ProFTPD Version ([0-9.a-z]+)", sock:sock);
  ftpVer = eregmatch(pattern:"Version ([0-9.]+)(rc[0-9])?", string:ftpVer[0]);

  if(ftpVer[1] != NULL)
  {
    if(ftpVer[2] != NULL)
      ftpVer = ftpVer[1] + "." + ftpVer[2];
    else
      ftpVer = ftpVer[1];

    if(ftpVer != NULL)
    {
      # Set KB for ProFTPD from File Version
      set_kb_item(name:"ProFTPD/Ver", value:ftpVer);
      security_note(data:"ProFTPD version " + ftpVer + " running at location "
                         + binPath + " was detected on the host");
      ssh_close_connection();

      ## build cpe and store it as host_detail
      cpe = build_cpe(value: ftpVer, exp:"^([0-9.]+)(rc[0-9]+)?",base:"cpe:/a:proftpd:proftpd:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
  }
}
ssh_close_connection();
