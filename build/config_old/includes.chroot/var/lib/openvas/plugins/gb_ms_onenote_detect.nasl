###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_onenote_detect.nasl 18 2013-10-27 14:14:13Z jan $
#
# Microsoft OneNote Version Detection (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "Detection of installed version of Microsoft OneNote.

  The script logs in via smb, and detect the version of Microsoft OneNote
  on remote host and sets the KB";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803436";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 18 $");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:14:13 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-13 11:28:48 +0530 (Wed, 13 Mar 2013)");
  script_name("Microsoft OneNote Version Detection (Windows)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("Detection of installed version of Microsoft OneNote on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");
include("secpod_smb_func.inc");
include("version_func.inc");

## Variable Initialization
exePath = "";
noteVer = "";
share = "";
file = "";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

# Check Office Installation
if(!registry_key_exists(key:"SOFTWARE\Microsoft\Office")){
  exit(0);
}

# Get OneNote Installed Path
exePath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                              "\App Paths\OneNote.exe", item:"Path");

if(exePath != NULL)
{
  noteVer = fetch_file_version(sysPath:exePath, file_name:"onenote.exe");

  # Set KB for onenote.exe File Version
  if(noteVer)
  {
    set_kb_item(name:"MS/Office/OneNote/Ver", value:noteVer);

    ## Build cpe
    cpe = build_cpe(value:noteVer, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:onenote:");
    if(isnull(cpe))
      cpe = 'cpe:/a:microsoft:onenote';

    register_product(cpe:cpe, location:exePath, nvt:SCRIPT_OID);
    log_message(data: build_detection_report(app:"Microsoft OneNote",
                                    version:noteVer, install:exePath,
                                        cpe:cpe, concluded:noteVer));
  }
}
