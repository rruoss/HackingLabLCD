###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ibm_lotus_domino_xss_n_bof_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# IBM Lotus Domino Cross Site Scripting and Buffer Overflow Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation may allow remote attackers to execute arbitrary code
  with system-level privileges or steal cookie-based authentication credentials
  and launch other attacks.
  Impact Level: System/Application";
tag_affected = "IBM Lotus Domino Versions 8.5.2 and prior.";
tag_insight = "- Input passed via the 'PanelIcon' parameter in an fmpgPanelHeader ReadForm
    action to WebAdmin.nsf is not properly sanitised before being returned to
    the user. This can be exploited to execute arbitrary HTML and script code
    in a user's browser session in context of an affected site.
  - Stack-based buffer overflow error in the NSFComputeEvaluateExt function
    in Nnotes.dll allows remote authenticated users to execute arbitrary code
    via a long 'tHPRAgentName' parameter in an fmHttpPostRequest OpenForm
    action to WebAdmin.nsf.";
tag_solution = "No solution or patch is available as of 23rd September, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www-01.ibm.com/software/lotus/products/domino/";
tag_summary = "The host is running IBM Lotus Domino Server and is prone to cross
  site scripting and buffer overflow vulnerabilities.";

if(description)
{
  script_id(902572);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-09-23 16:39:49 +0200 (Fri, 23 Sep 2011)");
  script_bugtraq_id(49701, 49705);
  script_cve_id("CVE-2011-3575", "CVE-2011-3576");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("IBM Lotus Domino Cross Site Scripting and Buffer Overflow Vulnerabilities");
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
  script_summary("Check for the version of IBM Lotus Domino");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("General");
  script_dependencies("gb_lotus_domino_detect.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/69802");
  script_xref(name : "URL" , value : "http://www.research.reversingcode.com/index.php/advisories/73-ibm-ssd-1012211");
  script_xref(name : "URL" , value : "http://www.research.reversingcode.com/exploits/IBMLotusDomino_StackOverflowPoC");
  exit(0);
}


include("version_func.inc");

## Get Lotus Domino Version from KB
domVer = get_kb_item("Domino/Version");
domPort = get_kb_item("Domino/Port/");
if(!domVer || !domPort){
  exit(0);
}

domVer = ereg_replace(pattern:"FP", string:domVer, replace: ".FP");

## Check for Vulnerable Lotus Domino Versions
if(version_is_less_equal(version:domVer, test_version:"8.5.2")) {
  security_hole(domPort);
}
