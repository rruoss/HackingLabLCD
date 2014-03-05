###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_gale_sec_bypass_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Gale EVP_VerifyFinal() Security Bypass Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation could allow remote attackers to bypass the certificate
  validation checks and can cause spoofing attacks via signature checks on DSA
  and ECDSA keys used with SSL/TLS.
  Impact Level: System/Application";
tag_affected = "Gale version 0.99 and prior on Linux.";
tag_insight = "The flaw is due to improper validation of return value in
  EVP_VerifyFinal function of openssl.";
tag_solution = "No solution or patch is available as of 19th January, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.gale.org/";
tag_summary = "The host is running Gale and is prone to security bypass
  vulnerability.";

if(description)
{
  script_id(800340);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-01-19 13:47:40 +0100 (Mon, 19 Jan 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-0047");
  script_bugtraq_id(33150);
  script_name("Gale EVP_VerifyFinal() Security Bypass Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/499855");
  script_xref(name : "URL" , value : "http://www.ocert.org/advisories/ocert-2008-016.html");
  script_xref(name : "URL" , value : "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2009-0047");

  script_description(desc);
  script_summary("Check for the Version of Gale");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_gale_detect.nasl");
  script_require_keys("Gale/Linux/Ver");
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

galePort = 11512;
if(!get_udp_port_state(galePort)){
  exit(0);
}

galeVer = get_kb_item("Gale/Linux/Ver");
if(!galeVer){
  exit(0);
}

# version 0.99 and prior
if(version_is_less_equal(version:galeVer, test_version:"0.99")){
  security_warning(galePort);
}
