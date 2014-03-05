###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_livecycle_designer_untrusted_search_path_vuln_win.nasl 12 2013-10-27 11:15:33Z jan $
#
# Adobe LiveCycle Designer Untrusted Search Path Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary code
  on the target system.
  Impact Level: System/Application";
tag_affected = "Adobe LiveCycle Designer version ES2 9.0.0.20091029.1.612548 on Windows";
tag_insight = "The flaw is due to the way it loads dynamic-link libraries. The program
  uses a fixed path to look for specific files or libraries. This path includes
  directories that may not be trusted or under user control. By placing a
  custom version of the file or library in the path, the program will load it
  before the legitimate version.";
tag_solution = "No solution or patch is available as of 25th, September 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.adobe.com/downloads/";
tag_summary = "This host is installed with Adobe LiveCycle Designer and is prone to
  untrusted search path vulnerability.";

if(description)
{
  script_id(802960);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2010-5212");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-09-11 19:03:45 +0530 (Tue, 11 Sep 2012)");
  script_name("Adobe LiveCycle Designer Untrusted Search Path Vulnerability (Windows)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41417");
  script_xref(name : "URL" , value : "http://www.osvdb.org/show/osvdb/68016");

  script_description(desc);
  script_summary("Check for the version of Adobe LiveCycle Designer on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_livecycle_designer_detect_win.nasl");
  script_require_keys("Adobe/LiveCycle/Designer");
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

# Variable Initialization
designVer = "";

# Get Adobe Flash Player Version
designVer = get_kb_item("Adobe/LiveCycle/Designer");
if(!designVer){
  exit(0);
}

## Check for Adobe LiveCycle Designer version (9000.2302.1.0)9.0.0.20091029.1.612548
## 9.0.0.20091029.1.612548 is the product version and 9000.2302.1.0 is the file verison
## Checking for the file verison, not able to get the product verison
if(version_is_equal(version:designVer, test_version:"9000.2302.1.0")){
  security_hole(0);
}
