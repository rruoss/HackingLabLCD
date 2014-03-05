###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_ie_neutering_xss_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Microsoft Internet Explorer 'neutering' Mechanism  XSS Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attackers to conduct cross-site
  scripting (XSS) attacks on the affected system.
  Impact Level: System/Application";
tag_affected = "Microsoft Internet Explorer version 8.x";
tag_insight = "The XSS filter in Internet Explorer does not perform neutering for the SCRIPT
  tag which allows attackers to conduct cross-site scripting attacks.";
tag_solution = "No solution or patch is available as of 22th April, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.microsoft.com/windows/internet-explorer/default.aspx";
tag_summary = "This host is installed with Internet Explorer and is prone to
  cross-site scripting vulnerability.";

if(description)
{
  script_id(902166);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-04-23 17:57:39 +0200 (Fri, 23 Apr 2010)");
  script_cve_id("CVE-2010-1489");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Microsoft Internet Explorer 'neutering' Mechanism XSS Vulnerability");
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
  script_xref(name : "URL" , value : "http://p42.us/ie8xss/");
  script_xref(name : "URL" , value : "http://p42.us/ie8xss/Abusing_IE8s_XSS_Filters.pdf");
  script_xref(name : "URL" , value : "http://blogs.technet.com/msrc/archive/2010/04/19/guidance-on-internet-explorer-xss-filter.aspx");

  script_description(desc);
  script_summary("Check for the version of Internet Explorer");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_require_keys("MS/IE/Version");
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

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

# Check for Internet Explorer version
if(version_in_range(version:ieVer, test_version:"8.0", test_version2:"8.0.6001.18702")){
  security_warning(0);
}
