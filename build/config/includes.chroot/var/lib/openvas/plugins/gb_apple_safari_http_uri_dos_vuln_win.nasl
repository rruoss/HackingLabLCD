###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_http_uri_dos_vuln_win.nasl 15 2013-10-27 12:49:54Z jan $
#
# Apple Safari Malformed URI Remote DoS Vulnerability (Win)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Browser crash (application termination) could be the result when attacker
  executes arbitrary codes.
  Impact Level: Application";
tag_affected = "Apple Safari 3.2.1 and prior on Windows (Any).";
tag_insight = "Malformed HTTP domain name can cause the safari web browser to a infinite
  loop which leads to memory violation when it tries to resolve the domain,
  or when it tries to write a section that contains unknown data.";
tag_solution = "No solution or patch is available as of 02nd February, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to  http://www.apple.com/support/downloads";
tag_summary = "This host is installed with Apple Safari web browser and is prone
  to denial of service vulnerability.";

if(description)
{
  script_id(800409);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-03 15:40:18 +0100 (Tue, 03 Feb 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-0321");
  script_bugtraq_id(33481);
  script_name("Apple Safari Malformed URI Remote DoS Vulnerability (Win)");
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
  script_xref(name : "URL" , value : "http://lostmon.blogspot.com/2009/01/safari-for-windows-321-remote-http-uri.html");

  script_description(desc);
  script_summary("Check for the version of Apple Safari");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_reg_enum.nasl",
                      "secpod_apple_safari_detect_win_900003.nasl");
  script_require_keys("AppleSafari/Version");
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

safVer = get_kb_item("AppleSafari/Version");
if(!safVer){
  exit(0);
}

# Grep for Apple Safari Version <= 3.2.1 (3.525.27.1)
if(version_is_less_equal(version:safVer, test_version:"3.525.27.1")){
  security_warning(0);
}
