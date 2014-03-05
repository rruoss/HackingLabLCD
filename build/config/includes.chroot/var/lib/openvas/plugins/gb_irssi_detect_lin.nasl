###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_irssi_detect_lin.nasl 15 2013-10-27 12:49:54Z jan $
#
# Irssi Version Detection (Linux)
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
tag_summary = "This script detects the installed version of Irssi and sets
  the result in KB.";

if(description)
{
  script_id(800633);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-06-19 09:45:44 +0200 (Fri, 19 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Irssi Version Detection (Linux)");
  desc = "

  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Sets KB for the version of Irssi");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800633";
SCRIPT_DESC = "Irssi Version Detection (Linux)";

irrsi_sock = ssh_login_or_reuse_connection();
if(!irrsi_sock){
  exit(0);
}

paths = find_bin(prog_name:"irssi", sock:irrsi_sock);

foreach irssibin (paths)
{
  irssiVer = get_bin_version(full_prog_name:chomp(irssibin), sock:irrsi_sock,
                             version_argv:"--version",
                             ver_pattern:"irssi (([0-9]\.[0-9.]+)-?(rc[0-9])?)");
  if(irssiVer[1] != NULL)
  {
    irssiVer = ereg_replace(pattern:"-", replace:".", string:irssiVer[1]);
    if(irssiVer != NULL)
    {
      set_kb_item(name:"Irssi/Lin/Ver", value:irssiVer);
      security_note(data:"Irssi version " + irssiVer + " running at location "
                         + irssibin +  " was detected on the host");
      ssh_close_connection();
      
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:irssiVer, exp:"^([0-9.]+)", base:"cpe:/a:irssi:irssi:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);


      exit(0);
    }
  }
}
ssh_close_connection();
