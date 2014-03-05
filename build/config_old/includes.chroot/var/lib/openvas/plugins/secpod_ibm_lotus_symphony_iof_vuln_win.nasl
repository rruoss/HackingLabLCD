###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ibm_lotus_symphony_iof_vuln_win.nasl 12 2013-10-27 11:15:33Z jan $
#
# IBM Lotus Symphony Image Object Integer Overflow Vulnerability (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary code in
  the context of affected applications. Failed exploit attempts will likely
  result in denial-of-service conditions.
  Impact Level: Application";
tag_affected = "IBM Lotus Symphony versions 3.0.0 FP3 and prior.";
tag_insight = "The flaw is due to an integer overflow error when processing embedded
  image objects. This can be exploited to cause a heap-based buffer overflow
  via a specially crafted JPEG object within a DOC file.";
tag_solution = "Upgrade to IBM Lotus Symphony version 3.0.1 or later,
  For updates refer to http://www.ibm.com/software/lotus/symphony/home.nsf/home";
tag_summary = "This host is installed with IBM Lotus Symphony and is prone to
  integer overflow vulnerability.";

if(description)
{
  script_id(902808);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-0192");
  script_bugtraq_id(51591);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-01-25 12:12:12 +0530 (Wed, 25 Jan 2012)");
  script_name("IBM Lotus Symphony Image Object Integer Overflow Vulnerability (Windows)");
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


  script_description(desc);
  script_summary("Check for the version of IBM Lotus Symphony");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("General");
  script_dependencies("gb_ibm_lotus_symphony_detect_win.nasl");
  script_require_keys("IBM/Lotus/Symphony/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47245");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51591");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/72424");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21578684");
  exit(0);
}


include("version_func.inc");

## Get version from KB
version = get_kb_item("IBM/Lotus/Symphony/Win/Ver");

## Check for IBM Lotus Symphony Versions 3.0.0 FP3 and prior
if(version_is_less_equal(version:version, test_version:"3.0.10289")){
  security_hole(0);
}
