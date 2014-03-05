###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ibm_informix_dynamic_server_detect_win.nasl 44 2013-11-04 19:58:48Z jan $
#
# IBM Informix Dynamic Server Version Detection (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_summary = "This script finds the installed IBM Informix Dynamic Server version
  and saves the version in KB.";

if(description)
{
  script_id(902545);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 44 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2011-08-02 09:08:31 +0200 (Tue, 02 Aug 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("IBM Informix Dynamic Server Version Detection (Windows)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set the Version of IBM Informix Dynamic Server in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902545";
SCRIPT_DESC = "IBM Informix Dynamic Server Version Detection (Windows)";

## Confirm Windows
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Confirm IBM Informix Dynamic Server
if(!registry_key_exists(key:"SOFTWARE\IBM\IBM Informix Dynamic Server")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)) {
  exit(0);
}

## Get Version From Registry
foreach item (registry_enum_keys(key:key))
{
  name = registry_get_sz(key:key + item, item:"DisplayName");
  if("IBM Informix Dynamic Server" >< name)
  {
    version = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(version)
    {
      ## Set IBM Informix Dynamic Server Version in KB
      set_kb_item(name:"IBM/Informix/Dynamic/Server/Win/Ver", value:version);
      security_note(data:"IBM Informix Dynamic Server " + version +
                         " was detected on the host");

      ## build cpe and store it as host_detail
      cpe = build_cpe(value: version, exp:"^([0-9.]+)",base:"cpe:/a:ibm:informix_dynamic_server:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
    }
  }
}
