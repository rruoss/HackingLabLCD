###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bind_sec_bypass_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# OpenSSL DSA_verify() Security Bypass Vulnerability in BIND
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
  validation checks and can cause man-in-the-middle attack via signature checks 
  on DSA and ECDSA keys used with SSL/TLS.
  Impact Level: Application";
tag_affected = "ISC BIND version prior to 9.2 or 9.6.0 P1 or 9.5.1 P1 or 9.4.3 P1 or 9.3.6 P1/Linux";
tag_insight = "The flaw is due to improper validation of return value from OpenSSL's
  DSA_do_verify and VP_VerifyFinal functions.";
tag_solution = "Upgrade to version 9.6.0 P1, 9.5.1 P1, 9.4.3 P1, 9.3.6 P1
  https://www.isc.org/downloadables/11";
tag_summary = "The host is running BIND and is prone to Security Bypass
  Vulnerability.";

if(description)
{
  script_id(800338);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-01-15 16:11:17 +0100 (Thu, 15 Jan 2009)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2008-5077", "CVE-2009-0025", "CVE-2009-0265");
  script_bugtraq_id(33150, 33151);
  script_name("OpenSSL DSA_verify() Security Bypass Vulnerability in BIND");
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
  script_xref(name : "URL" , value : "https://www.isc.org/node/373");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/33404/");
  script_xref(name : "URL" , value : "http://www.ocert.org/advisories/ocert-2008-016.html");

  script_description(desc);
  script_summary("Check for the Version of BIND");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("bind_version.nasl");
  script_require_keys("bind/version");
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
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0); # this nvt is prone to FP

udpPort = 53;
if(!get_udp_port_state(udpPort)){
  exit(0);
}

bindVer = get_kb_item("bind/version");
if(!bindVer){
  exit(0);
}

bindVer = eregmatch(pattern:"([0-9.]+)[-| ]?([a-zA-Z0-9]+)?", string:bindVer);
if(bindVer[1] != NULL)
{
  if(bindVer[2] =~ "[a-zA-Z0-9]+"){
    bindVer = bindVer[1] + "." + bindVer[2];
  }
  else
    bindVer = bindVer[1];

  # Check for version < 9.2 or 9.6.0 P1 or 9.5.1 P1 or 9.4.3 P1 or 9.3.6 P1
  if(version_in_range(version:bindVer, test_version:"9.6", test_version2:"9.6.0") ||
     version_in_range(version:bindVer, test_version:"9.5", test_version2:"9.5.1") ||
     version_in_range(version:bindVer, test_version:"9.4", test_version2:"9.4.3") ||
     version_in_range(version:bindVer, test_version:"9.3", test_version2:"9.3.6") ||
     version_is_less(version:bindVer, test_version:"9.2")){
    security_hole(port:udpPort, proto:"udp");
  }
}
