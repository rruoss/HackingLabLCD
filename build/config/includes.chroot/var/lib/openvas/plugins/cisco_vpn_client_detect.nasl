# OpenVAS Vulnerability Test
# $Id: cisco_vpn_client_detect.nasl 42 2013-11-04 19:41:32Z jan $
# Description: Cisco VPN Client Version Detection
#
# Authors:
# Ferdy Riphagen 
# Modified by Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2007 Ferdy Riphagen
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_summary = "This script is detects the installed version of Cisco VPN
 Client and sets the result in KB.";

if (description) {
 script_id(80037);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 42 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:41:32 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2008-10-24 20:38:19 +0200 (Fri, 24 Oct 2008)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_description(desc);

 name = "Cisco VPN Client Version Detection";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary; script_description(desc);
 summary = "Detects the version number of the Cisco VPN Client in use";
 script_summary(summary);
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2007 Ferdy Riphagen");
 script_require_ports(139, 445);
 script_dependencies("secpod_reg_enum.nasl");
 script_require_keys("SMB/login", "SMB/password", "SMB/name", "SMB/transport");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.80037";
SCRIPT_DESC = "Cisco VPN Client Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
 exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Cisco Systems\VPN Client")){
  exit(0);  
}

key = "SOFTWARE\Cisco Systems\VPN Client";
path = registry_get_sz(key:key, item:"InstallPath");

if(path)
{
  file = path + "\vpngui.exe";
  version = GetVersionFromFile(file:file,verstr:"prod");
  if(!isnull(version)){
    set_kb_item(name:"SMB/CiscoVPNClient/Version", value:version);
   
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:llnl:slurm:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    exit(0);
  } 
}

exit(0);
