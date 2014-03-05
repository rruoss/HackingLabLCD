###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ntp_detect_lin.nasl 15 2013-10-27 12:49:54Z jan $
#
# NTP Version Detection (Linux)
#
# Authors:
# Chandan S <schandan@secpod.com>
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
tag_summary = "The script detects the installed version of NTP and saves
  the result in KB.";

if(description)
{
  script_id(800407);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-01-15 16:11:17 +0100 (Thu, 15 Jan 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("NTP Version Detection (Linux)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the version of NTP");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("ntp_open.nasl","ssh_authorization.nasl");
  script_mandatory_keys("login/SSH/success");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800407";
SCRIPT_DESC = "NTP Version Detection (Linux)";

ntpVersion = get_kb_item("NTP/Linux/Ver");
if(!ntpVersion)
{
  sock = ssh_login_or_reuse_connection();
  if(!sock){
   exit(0);
  }

  binFiles = find_file(file_name:"ntpd",file_path:"/", useregex:TRUE,
                    regexpar:"$", sock:sock);
  foreach binName (binFiles)
  {
    ntpVer = get_bin_version(full_prog_name:chomp(binName), sock:sock,
             version_argv:"--version",
             ver_pattern:"ntpd.* ([0-9]\.[0-9.]+)([a-z][0-9]+)?-?(RC[0-9])?");
    if(ntpVer[1] != NULL)
    {
      if(ntpVer[2] =~ "[a-z][0-9]+" && ntpVer[3] =~ "RC"){
        ntpVer = ntpVer[1] + "." + ntpVer[2] + "." + ntpVer[3];
       }
      else if(ntpVer[2] =~ "[a-z][0-9]+"){
        ntpVer = ntpVer[1] + "." + ntpVer[2];
       }
      else ntpVer = ntpVer[1];

      set_kb_item(name:"NTP/Linux/Ver", value:ntpVer);
      security_note(data:" NTP version " + ntpVer + " running at location " 
                    + binName + " was detected on the host");
      ssh_close_connection();
   
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:ntpVer, exp:"^([0-9.]+([a-z0-9]+)?)", base:"cpe:/a:ntp:ntp:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

      exit(0);
    }
  }
  ssh_close_connection();
}
