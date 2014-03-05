###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_silverlight_multiple_memory_leak_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Microsoft Silverlight Multiple Memory Leak Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attacker to cause denial of service.
  Impact Level: Application";
tag_affected = "Microsoft Silverlight version 4 before 4.0.60310.0";
tag_insight = "The flaws exists due to:
  - An error in handling of 'popup' control and a custom 'DependencyProperty'
    property.
  - An error in the 'DataGrid' control implementation, which allows remote
    attacker to consume memory via an application involving subscriptions to
    an INotifyDataErrorInfo.ErrorsChanged event or TextBlock or a TextBox
    element.";
tag_solution = "Upgrade to Microsoft Silverlight 4.0.60310.0 or later,
  For updates refer to http://www.microsoft.com/getsilverlight/Get-Started/Install/Default.aspx";
tag_summary = "This host is installed with Microsoft Silverlight and is prone to
  to multiple memory leak vulnerabilities.";

if(description)
{
  script_id(801935);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-05-16 15:25:30 +0200 (Mon, 16 May 2011)");
  script_cve_id("CVE-2011-1844", "CVE-2011-1845");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_name("Microsoft Silverlight Multiple Memory Leak Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2526954");
  script_xref(name : "URL" , value : "http://isc.sans.edu/diary.html?storyid=10747");

  script_description(desc);
  script_summary("Check for the version of Microsoft Silverlight");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ms_silverlight_detect.nasl");
  script_require_keys("Microsoft/Silverlight");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("version_func.inc");

mslVer = get_kb_item("Microsoft/Silverlight");
if(!mslVer){
  exit(0);
}

# Check for Microsoft Silverlight 4 before 4.0.60310.0
if(version_in_range(version:mslVer, test_version:"4.0", test_version2:"4.0.60309.0")){
  security_hole(0);
}
