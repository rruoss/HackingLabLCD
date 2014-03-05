##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ws_ftp_client_detect.nasl 14 2013-10-27 12:33:37Z jan $
#
# Iswitch WS-FTP Client Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SePod, http://www.secpod.com
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
tag_summary = "This script finds the installed WS-FTPP Client version and saves
  the result in KB item.";

if(description)
{
  script_id(902170);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-04-23 17:57:39 +0200 (Fri, 23 Apr 2010)");
  script_name("Iswitch WS-FTP Client Version Detection");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set version of WS-FTP Client in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Service detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902170";
SCRIPT_DESC = "Iswitch WS-FTP Client Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Check for Product installation
if(!registry_key_exists(key:"SOFTWARE\Ipswitch\WS_FTP")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  ## Confirm Application aplication with name
  wsftpName = registry_get_sz(key:key + item, item:"DisplayName");
  if(("Ipswitch" >< wsftpName) || ("WS_FTP" >< wsftpName))
  {
    ## Check for Ws-FTP Professional
    wsftpIcon = registry_get_sz(key:key + item, item:"DisplayIcon");
    if("ftppro" >< wsftpIcon)
    {
      ## Grep for version
      wsftpVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      if(wsftpVer != NULL)
      {
        ## setting the verison of WS-FTP Professinal
        set_kb_item(name:"Ipswitch/WS_FTP_Pro/Client/Ver", value:wsftpVer);
        security_note(data:"WS_FTP version " + wsftpVer +
                           " was detected on the host");
      
        ## build cpe and store it as host_detail
        cpe = build_cpe(value:wsftpVer, exp:"^([0-9.]+)", base:"cpe:/a:ipswitch:ws_ftp:12.0:");
        if(!isnull(cpe))
           register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

        exit(0);
      }
    }
  }
}
