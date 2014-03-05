###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_firefox_location_hash_dos_vuln.nasl 16 2013-10-27 13:09:52Z jan $
#
# Mozilla Firefox location.hash Remote DoS Vulnerability
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 SecPod, http://www.secpod.com
#
# Updated to CVE-2009-2953 and Linux Version Checks, Issue: 4260
#  - By Sharath S <sharaths@secpod.com> On 2009-08-26
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
tag_summary = "The host is installed with Mozilla Firefox browser and is prone
  to denial of service vulnerability.

  Vulnerability:
  The flaw is due to improper way of handling input passed to
  location.hash.";

tag_impact = "Successful exploitation could result in remote arbitrary code execution,
  and can crash the affected browser.
  Impact Level: Application";
tag_affected = "Mozilla, Firefox version 3.0 through 3.0.13 and 3.5.x";
tag_solution = "Upgrade to Mozilla Firefox version 3.6.3 or later
  For updates refer to http://www.mozilla.org/";

if(description)
{
  script_id(900068);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-12-29 13:55:43 +0100 (Mon, 29 Dec 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2008-5715", "CVE-2009-2953");
  script_bugtraq_id(32988);
  script_name("Mozilla Firefox location.hash Remote DoS Vulnerability");
  desc = "

  Summary:
  " + tag_summary + "
  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "http://websecurity.com.ua/3424/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/32988/discuss");
  script_xref(name : "URL" , value : "http://downloads.securityfocus.com/vulnerabilities/exploits/32988.pl");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/506006/100/0/threaded");

  script_description(desc);
  script_summary("Check for the version of Firefox");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_firefox_detect_win.nasl","gb_firefox_detect_lin.nasl");
  script_require_keys("Firefox/Win/Ver", "Firefox/Linux/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("version_func.inc");

ffVer = get_kb_item("Firefox/Win/Ver");

if(!ffVer){
  ffVer = get_kb_item("Firefox/Linux/Ver");

  if(!ffVer)
    exit(0);
}

# Grep for firefox version 3.x to 3.0.13 and 3.5.x
if(version_in_range(version:ffVer, test_version:"3.0", test_version2:"3.0.13")||
   version_in_range(version:ffVer, test_version:"3.5", test_version2:"3.5.2")){
  security_warning(0);
}
