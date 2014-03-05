###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_select_dos_vuln_macosx.nasl 12 2013-10-27 11:15:33Z jan $
#
# Opera Web Browser Select Object Denial Of Service Vulnerability (Mac OS X)
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
tag_impact = "Successful exploitation will let the attacker crash the browser leading to
  denial of service.
  Impact Level: Application";
tag_affected = "Opera version 9.64 and prior on Mac OS X";
tag_insight = "The flaw is due to an improper boundary check while passing data into
  the select() method and can be exploited by passing a large integer value
  resulting in memory exhaustion.";
tag_solution = "Upgrade to opera version 10 beta 1 or later,
  For updates refer to http://www.opera.com/download";
tag_summary = "The host is installed with Opera Web Browser and is prone to select object
  denial of service vulnerability.";

if(description)
{
  script_id(802754);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2009-2540", "CVE-2009-1692");
  script_bugtraq_id(35446);
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-04-19 10:28:43 +0530 (Thu, 19 Apr 2012)");
  script_name("Opera Web Browser Select Object Denial Of Service Vulnerability (Mac OS X)");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9160");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/52874");
  script_xref(name : "URL" , value : "http://www.g-sec.lu/one-bug-to-rule-them-all.html");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/504969/100/0/threaded");

  script_description(desc);
  script_summary("Check for the version of Opera on Mac OS X");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_opera_detect_macosx.nasl");
  script_require_keys("Opera/MacOSX/Version");
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

## Variable Initialization
operaVer = "";

## Get Opera Version from KB
operaVer = get_kb_item("Opera/MacOSX/Version");
if(!operaVer){
  exit(0);
}

# Check for Opera version <= 9.64
if(version_is_less_equal(version:operaVer, test_version:"9.64")){
  security_hole(0);
}
