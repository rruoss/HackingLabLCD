###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novell_zhm_detect.nasl 14 2013-10-27 12:33:37Z jan $
#
# Novell ZENworks Handheld Management Version Detection
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "This script finds the installed Novell ZENworks Handheld Management
  version and saves the version in KB.";

if(description)
{
  script_id(801644);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-11-30 12:42:12 +0100 (Tue, 30 Nov 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Novell ZENworks Handheld Management Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set the Version of Novell ZENworks Handheld Management in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801644";
SCRIPT_DESC = "Novell ZENworks Handheld Management Version Detection";

## Confirm Windows
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Novell\ZENworks\Handheld Management\Server" ;

##Confirm the application installation
if(!registry_key_exists(key:key)){
  exit(0);
}

##Check the name
name = registry_get_sz(key:key, item:"Display Name");

if("ZENworks Handheld Management Server" >< name)
{
  ## Get Novell ZENworks Handheld Management version from registry
  ver = registry_get_sz(key:key, item:"Version");
  if(ver != NULL)
  {
    set_kb_item(name:"Novell/ZHM/Ver", value:ver);
    security_note(data: "Novell ZENworks Handheld Management version " + ver +
                      " was detected on the host");
      
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:ver, exp:"^([0-9.]+)", base:"cpe:/a:novell:zenworks_handheld_management:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

  }
}