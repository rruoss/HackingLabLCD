###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_ie_info_dis_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Microsoft Internet Explorer Information Disclosure Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary codes
  in the context of the web browser and can reveal sensitive information of
  the remote user through the web browser.
  Impact Level: Application";
tag_affected = "Microsoft Internet Explorer version 8 Beta2 and prior on Windows.";
tag_insight = "An unspecified function in the JavaScript implementation in Microsoft
  Internet Explorer creates and exposes temporary footprint when there is a
  current login to a web site, which makes it easier for remote attackers
  to trick a user into acting upon a spoofed pop-up message.";
tag_solution = "No solution or patch is available as of 22nd January 2009, Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to
  http://www.microsoft.com/windows/internet-explorer/download-ie.aspx";
tag_summary = "This host is installed with Internet Explorer and is prone to
  Information Disclosure vulnerability.";

if(description)
{
  script_id(900192);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-01-22 12:00:13 +0100 (Thu, 22 Jan 2009)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2008-5912");
  script_bugtraq_id(33276);
  script_name("Microsoft Internet Explorer Information Disclosure Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.trusteer.com/files/In-session-phishing-advisory-2.pdf");
  script_xref(name : "URL" , value : "http://www.darkreading.com/security/attacks/showArticle.jhtml?articleID=212900161");

  script_description(desc);
  script_summary("Check for the version of Internet Explorer");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
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

if(version_is_less_equal(version:ieVer, test_version:"8.0.6001.18241")){
  security_warning(0);
}
