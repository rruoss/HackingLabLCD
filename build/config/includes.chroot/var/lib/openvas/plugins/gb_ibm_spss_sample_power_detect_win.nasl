###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_spss_sample_power_detect_win.nasl 44 2013-11-04 19:58:48Z jan $
#
# IBM SPSS SamplePower Version Detection (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "Detection of installed version of IBM SPSS SamplePower.

The script logs in via smb, searches for IBM SPSS SamplePower in the registry
and gets the version from 'DisplayVersion' string in registry";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802299";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 44 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2012-02-01 10:10:10 +0530 (Wed, 01 Feb 2012)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"detection", value:"registry version check");
  script_name("IBM SPSS SamplePower Version Detection (Windows)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Detection of installed version of IBM SPSS SamplePower");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

## Confirm Windows
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Registry Key
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)) {
  exit(0);
}

## Get Version From Registry
foreach item (registry_enum_keys(key:key))
{
  name = registry_get_sz(key:key + item, item:"DisplayName");

  ## Confirm The Application
  if("SamplePower" >< name)
  {
    version = registry_get_sz(key:key + item, item:"DisplayVersion");
    location = registry_get_sz(key:key + item, item:"Readme");
    if(version)
    {
      ## Set IBM SPSS SamplePower Version in KB
      set_kb_item(name:"IBM/SPSS/Win/Ver", value:version);

      ## Build CPE
      cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:ibm:spss_samplepower:");
      if(!isnull(cpe))
        register_product(cpe:cpe, location:location, nvt:SCRIPT_OID);

      log_message(data:'Detected IBM SPSS SamplePower version: ' + version +
        '\nLocation: ' + location +
        '\nCPE: '+ cpe +
        '\n\nConcluded from version identification result:\n' +
        'IBM SPSS SamplePower '+ version);
    }
  }
}
