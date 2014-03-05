###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_icq_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# ICQ Version Detection
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
tag_summary = "This script detects the installed version of ICQ Client and
  sets the result in KB.";

if(description)
{
  script_id(800807);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-06-09 08:37:33 +0200 (Tue, 09 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("ICQ Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the version of ICQ");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800807";
SCRIPT_DESC = "ICQ Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

# Check for ICQ Installed or Not
if(!(registry_key_exists(key:"SOFTWARE\Mirabilis\ICQ") ||
     registry_key_exists(key:"SOFTWARE\ICQ"))){
  exit(0);
}

# To Get the Installed Location
icqPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion"+
                              "\App Paths\ICQ.exe", item:"Path");
if(icqPath == NULL){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:icqPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:icqPath + "\icq.exe");
icqVer = GetVer(share:share, file:file);

# Set KB for ICQ Version
if(icqVer != NULL)
{
  set_kb_item(name:"ICQ/Ver", value:icqVer);
  security_note(data:"ICQ version " + icqVer + " running at location" + icqPath +
                     " was detected on the host");
    
  ## build cpe and store it as host_detail
  cpe = build_cpe(value:icqVer, exp:"^([0-9]\.[0-9])", base:"cpe:/a:icq:icq:");
  if(!isnull(cpe))
     register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

}
