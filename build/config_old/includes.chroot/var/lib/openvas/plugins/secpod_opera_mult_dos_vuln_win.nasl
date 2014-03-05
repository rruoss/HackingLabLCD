###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_opera_mult_dos_vuln_win.nasl 14 2013-10-27 12:33:37Z jan $
#
# Opera Browser Multiple Denial Of Service Vulnerability (Windows)
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
tag_impact = "Successful exploitation will allow remote attackers to cause a denial of
  service.
  Impact Level: Application";
tag_affected = "Opera version 9.52 and prior on Windows.";
tag_insight = "Multiple flaws are due to,
  - Opera executes a mail application in situations where an 'IMG' element has
    a 'SRC' attribute that is a redirect to a mailto: URL, which allows remote
    attackers to launch excessive application via an HTML document with many
    images.
  - Improper handling of 'IFRAME' element with a mailto: URL in its 'SRC'
    attribute, which allows remote attackers to consume resources via an HTML
    document with many IFRAME elements.";
tag_solution = "No solution or patch is available as of 21st May, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.opera.com/download/?os=windows&list=all";
tag_summary = "The host is installed with Opera Web Browser and is prone to
  Multiple Denial of Service vulnerability.";

if(description)
{
  script_id(902182);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)");
  script_cve_id("CVE-2010-1989", "CVE-2010-1993");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Opera Browser Multiple Denial Of Service Vulnerability (Windows)");
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
  script_xref(name : "URL" , value : "http://websecurity.com.ua/4206/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/511327/100/0/threaded");

  script_description(desc);
  script_summary("Check for the version of Opera Web Browser");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_opera_detection_win_900036.nasl");
  script_require_keys("Opera/Win/Version");
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

## Get Opera version from from KB list
operaVer = get_kb_item("Opera/Win/Version");
if(!operaVer){
  exit(0);
}

## Check if version is lesser than 9.52
if(version_is_less_equal(version:operaVer, test_version:"9.52")){
  security_warning(0);
}
