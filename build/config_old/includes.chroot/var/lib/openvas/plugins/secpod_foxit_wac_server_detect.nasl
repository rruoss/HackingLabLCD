###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_foxit_wac_server_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# Foxit WAC Server Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "This script finds the version of Foxit WAC Server and
  saves the result in KB.";

if(description)
{
  script_id(900923);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-08-27 13:43:20 +0200 (Thu, 27 Aug 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Foxit WAC Server Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_family("Service detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_summary("Set version of Foxit WAC Server in KB");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_require_ports("Services/ssh", 22, "Services/telnet", 23);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("ssh_func.inc");
include("telnet_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900923";
SCRIPT_DESC = "Foxit WAC Server Version Detection";

sshdPort = get_kb_item("Services/ssh");
if(!sshdPort){
  sshdPort = 22;
}

telnetPort = get_kb_item("Services/telnet");
if(!telnetPort){
  telnetPort = 23;
}

foreach port (make_list(sshdPort, telnetPort))
{
  banner = get_kb_item("SSH/banner/" + port);
  if("WAC" >!< banner){
    banner = get_kb_item("telnet/banner/" + port);
  }

  wacserVer = eregmatch(pattern:"Server[-| ](([0-9.]+).?(([a-zA-Z]+[ 0-9]+))?)",
                       string: banner);
  if(wacserVer[1] != NULL)
  {
    wacVer = ereg_replace(pattern:" ", string:wacserVer[1], replace:".");
    if(wacVer != NULL){
      set_kb_item(name:"Foxit-WAC-Server/Ver", value:wacVer);
      security_note(data:"Foxit WAC Server version " + wacVer +
                                               " was detected on the host");

      ## build cpe and store it as host_detail
      cpe = build_cpe(value:wacVer, exp:"^([0-9.]+)", base:"cpe:/a:foxitsoftware:wac_server:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
  }
}
