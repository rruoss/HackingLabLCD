###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ntp_sec_bypass_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# NTP EVP_VerifyFinal() Security Bypass Vulnerability
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
tag_affected = "NTP version 4.2.4 to 4.2.4p5 and 4.2.5 to 4.2.5p150 on Linux.";
tag_insight = "The flaw is due to improper validation of return value in
  EVP_VerifyFinal function of openssl.";
tag_solution = "Upgrade to NTP version 4.2.4p6 or 4.2.5p151
  http://www.ntp.org/downloads.html";
tag_summary = "This host has NTP installed and is prone to security bypass
  vulnerability.";

if(description)
{
  script_id(800408);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-01-15 16:11:17 +0100 (Thu, 15 Jan 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-0021");
  script_bugtraq_id(33150);
  script_name("NTP EVP_VerifyFinal() Security Bypass Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/499827");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/499855");
  script_xref(name : "URL" , value : "http://www.ocert.org/advisories/ocert-2008-016.html");

  script_description(desc);
  script_summary("Check for the Version of NTP");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ntp_detect_lin.nasl");
  script_require_keys("NTP/Linux/Ver");
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

fullVer = get_kb_item("NTP/Linux/FullVer");
if(fullVer && fullVer == "ntpd 4.2.4p4@1.1520-o Sun Nov 22 17:34:54 UTC 2009 (1)") {
  exit(0); # debian backport
}

ntpVer = get_kb_item("NTP/Linux/Ver");
if(!ntpVer){
  exit(0);
}

# version 4.2.4 t0 4.2.4.p5 and 4.2.5 to 4.2.5.p150
if(version_in_range(version:ntpVer, test_version:"4.2.4",
                    test_version2:"4.2.4.p5")||
   version_in_range(version:ntpVer, test_version:"4.2.5",
                    test_version2:"4.2.5.p150")){
  security_warning(port:ntpPort, proto:"udp");
}
