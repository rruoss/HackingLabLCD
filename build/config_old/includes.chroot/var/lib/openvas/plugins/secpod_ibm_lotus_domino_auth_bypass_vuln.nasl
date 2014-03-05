###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ibm_lotus_domino_auth_bypass_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# IBM Lotus Domino Cookie File Authentication Bypass Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation may allow remote attackers to bypass the authentication
  mechanism by providing a malicious UNC path to COOKIEFILE.
  Impact Level: Application/System";
tag_affected = "IBM Lotus Domino versions 7.x and 8.x";
tag_insight = "The flaw is due to an error in the Server Controller authentication
  mechanism, which does not properly verify the COOKIEFILE path before using
  it to retrieve user's credentials.";
tag_solution = "No solution or patch is available as of 28th April 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www-01.ibm.com/software/lotus/products/domino/";
tag_summary = "The host is running IBM Lotus Domino Server and is prone to
  authentication bypass vulnerability";

if(description)
{
  script_id(902420);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-05-09 15:38:03 +0200 (Mon, 09 May 2011)");
  script_cve_id("CVE-2011-1519", "CVE-2011-1520");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("IBM Lotus Domino Cookie File Authentication Bypass Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43860");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0758");
  script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-11-110/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/517119/100/0/threaded");

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
  exit(0);
}


## Get Lotus Domino Version from KB
domVer = get_kb_item("Domino/Version");
domPort = get_kb_item("Domino/Port/");
if(!domVer || !domPort){
  exit(0);
}

## Check for Vulnerable Lotus Domino Versions
if(domVer =~ "^(7|8)\..*"){
  security_hole(domPort);
}
