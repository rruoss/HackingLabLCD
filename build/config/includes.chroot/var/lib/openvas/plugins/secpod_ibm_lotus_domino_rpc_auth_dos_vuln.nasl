###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ibm_lotus_domino_rpc_auth_dos_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# IBM Lotus Domino Notes RPC Authentication Processing Denial of Service Vulnerability
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
tag_impact = "Successful exploitation may allow remote attackers to cause a denial
  of service via a specially crafted packet.
  Impact Level: Application";
tag_affected = "IBM Lotus Domino Versions 8.x before 8.5.2 FP4";
tag_insight = "The flaw is due to an error when processing certain RPC operations
  related to authentication and can be exploited to crash the Domino server
  via a specially crafted packet.";
tag_solution = "Upgrade to IBM Lotus Domino version 8.5.2 FP4 or 8.5.3 or later
  For updates refer to http://www-01.ibm.com/software/lotus/products/domino/";
tag_summary = "The host is running IBM Lotus Domino Server and is prone to denial
  of service vulnerability.";

if(description)
{
  script_id(2497);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2011-1393");
  script_bugtraq_id(51167);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-12-29 10:48:29 +0530 (Thu, 29 Dec 2011)");
  script_name("IBM Lotus Domino Notes RPC Authentication Processing Denial of Service Vulnerability");
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
  script_family("Denial of Service");
  script_dependencies("gb_lotus_domino_detect.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://osvdb.org/77990");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47331");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/71805");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21575247");
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
if(version_in_range(version:domVer, test_version:"8.0", test_version2:"8.5.2.FP3")){
  security_hole(domPort);
}
