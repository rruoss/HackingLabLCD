###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_win_media_services_actvx_bof_vuln.nasl 16 2013-10-27 13:09:52Z jan $
#
# Microsoft Windows Media Services nskey.dll ActiveX BOF Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_solution = "No solution or patch is available as of 27th November, 2008. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to
  http://www.microsoft.com/windows/windowsmedia/forpros/server/server.aspx

  Workaround: Set a kill bit for the CLSID
  {2646205B-878C-11D1-B07C-0000C040BCDB}";

tag_impact = "Successful exploitation could allow execution of arbitrary code, and cause the
  victim's browser to crash.
  Impact Level: Application";
tag_affected = "Microsoft Windows Media Services on Windows NT/2000 Server.";
tag_insight = "The flaw is due to an error in CallHTMLHelp method in nskey.dll file,
  which fails to perform adequate boundary checks on user-supplied input.";
tag_summary = "This host is installed with Windows Media Services and is prone to
  Buffer Overflow vulnerability.";

if(description)
{
  script_id(800310);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-11-27 14:04:10 +0100 (Thu, 27 Nov 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2008-5232");
  script_bugtraq_id(30814);
  script_name("Microsoft Windows Media Services nskey.dll ActiveX BOF Vulnerability");
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

  script_xref(name : "URL" , value : "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2008-5232");
  script_xref(name : "URL" , value : "http://downloads.securityfocus.com/vulnerabilities/exploits/30814.html.txt");

  script_description(desc);
  script_summary("Check for the Version of Windows Media Services");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

wmsPath = registry_get_sz(key:"SYSTEM\ControlSet001\Services\nsmonitor",
                          item:"ImagePath");
if(!wmsPath){
  exit(0);
}

wmsPath = wmsPath - "nspmon.exe" + "nskey.dll";
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:wmsPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:wmsPath);

wmsVer = GetVer(file:file, share:share);
if(wmsVer == NULL){
  exit(0);
}

if(version_is_less_equal(version:wmsVer, test_version:"4.1.00.3917"))
{
  # Check if Kill-Bit is set for ActiveX control
  clsid = "{2646205B-878C-11D1-B07C-0000C040BCDB}";
  regKey = "SOFTWARE\Classes\CLSID\" + clsid;
  if(registry_key_exists(key:regKey))
  {
    activeKey = "SOFTWARE\Microsoft\Internet Explorer\ActiveX Compatibility\" + clsid;
    killBit = registry_get_dword(key:activeKey, item:"Compatibility Flags");
    if(killBit && (int(killBit) == 1024)){
      exit(0);
    }
    security_hole(0);
  }
}
