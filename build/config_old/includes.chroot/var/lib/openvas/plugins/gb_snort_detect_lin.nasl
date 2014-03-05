###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_snort_detect_lin.nasl 15 2013-10-27 12:49:54Z jan $
#
# Snort Version Detection (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_summary = "This script detects the installed version of Snort and
  sets the reuslt in KB.";

if(description)
{
  script_id(801138);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-11-02 14:39:30 +0100 (Mon, 02 Nov 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Snort Version Detection (Linux)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the version of Snort");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801138";
SCRIPT_DESC = "Snort Version Detection (Linux)";

snortSock = ssh_login_or_reuse_connection();
if(!snortSock){
  exit(0);
}

paths = find_bin(prog_name:"snort",sock:snortSock);
foreach binName (paths)
{
  snortVer = get_bin_version(full_prog_name:chomp(binName), version_argv:"-V",
                             ver_pattern:"> Snort! <", sock:snortSock);
  snortVer = eregmatch(pattern:"Version ([0-9.]+)( \(Build.?([0-9]+)\))?",
                       string:snortVer[1], icase:1);
  if(snortVer[1])
  {
    set_kb_item(name:"Snort/Linux/Ver", value:snortVer[1]);
    if(snortVer[3])
    {
      snortVer = snortVer[1] + "." + snortVer[3];
      set_kb_item(name:"Snort/Linux/Build", value:snortVer);
      security_note(data:"Snort version " + snortVer + " running at location " 
                      + binName + " was detected on the host");
  
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:snortVer, exp:"^([0-9.]+)", base:"cpe:/a:snort:snort:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
  }
}
ssh_close_connection();
