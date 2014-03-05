###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_avg_detect_win.nasl 43 2013-11-04 19:51:40Z jan $
#
# AVG AntiVirus Version Detection (Win)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http//www.secpod.com
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
tag_summary = "Detection of installed version of AVG AntiVirus

The script logs in via smb, searches for AVG AntiVirus in the registry
and gets the version from registry";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900718";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 43 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-05-29 07:35:11 +0200 (Fri, 29 May 2009)");
  script_tag(name:"detection", value:"registry version check");
  script_name("AVG AntiVirus Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("Set Version of AVG AntiVirus in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");

## Variable Initilazation
ver = "";
avgVer = "";
avgPath = "";
cpe = "";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\AVG")){
  exit(0);
}

foreach ver (make_list("1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "2012", "2013"))
{
  avgVer = registry_get_sz(key:"SOFTWARE\AVG\AVG" + ver +
                               "\LinkScanner\Prevalence", item:"CODEVER");

  avgPath = registry_get_sz(key:"SOFTWARE\AVG\AVG" + ver +
                               "\LinkScanner", item:"AppPath");
  if(!avgPath){
    avgPath = "Could not find the install location from registry";
  }

  if(avgVer)
  {
    set_kb_item(name:"AVG/AV/Win/Ver", value:avgVer);
    security_note(data:"AVG AntiVirus version " + avgVer + " was detected on the host");

    ## build cpe and store it as host_detail
    cpe = build_cpe(value: avgVer, exp:"^([0-9.]+)",base:"cpe:/a:avg:avg_anti-virus:");
    if(isnull(cpe))
      cpe = "cpe:/a:avg:avg_anti-virus";

    log_message(data: build_detection_report(app:"AVG AntiVirus",
                                           version:avgVer, install:avgPath,
                                           cpe:cpe, concluded: avgVer));
    exit(0);
  }
}
