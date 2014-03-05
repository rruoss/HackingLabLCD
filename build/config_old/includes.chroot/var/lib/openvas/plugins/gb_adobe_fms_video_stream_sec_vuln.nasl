###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_fms_video_stream_sec_vuln.nasl 16 2013-10-27 13:09:52Z jan $
#
# Adobe Flash Media Server Video Stream Capture Security Issue
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful attack could lead to capture and archive delivered video.
  Impact Level: Application";
tag_affected = "Adobe Flash Media Server 3.0 and prior on Windows.";
tag_insight = "The security issue is that it is possible to establish RTMPE/RTMPTE sessions
  to Flash Media Server when SWF verification is not enabled.";
tag_solution = "Upgrade Adobe Flash Media Server version 3.0.5 or later,
  For updates refer to http://www.adobe.com/products/flashmediaserver/";
tag_summary = "The host is running Adobe Flash Media Server (FMS), and is prone
  to video streaming vulnerability.";

if(description)
{
  script_id(800069);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-11-27 14:04:10 +0100 (Thu, 27 Nov 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2008-5109");
  script_name("Adobe Flash Media Server Video Stream Capture Security Issue");
  desc = "

  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/advisories/apsa08-11.html");

  script_description(desc);
  script_summary("Check for the Version of Adobe FMS");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

fmsPort = 1935;
if(!get_port_state(fmsPort)){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach entry (registry_enum_keys(key:key))
{
  fmsVer = registry_get_sz(key:key + entry, item:"DisplayName");
  if("Adobe Flash Media Server" >< fmsVer)
  {
    fmsVer = eregmatch(pattern:"[0-9.]+", string:fmsVer);
    if(fmsVer[0] != NULL)
    {
      if(version_is_less(version:fmsVer[0], test_version:"3.0.1")){
        security_warning(fmsPort);
      }
    }
    exit(0);
  }
}
