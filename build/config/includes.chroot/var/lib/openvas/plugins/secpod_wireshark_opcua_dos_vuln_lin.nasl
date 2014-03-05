###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wireshark_opcua_dos_vuln_lin.nasl 15 2013-10-27 12:49:54Z jan $
#
# Wireshark OpcUa Dissector Denial of Service Vulnerability (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation could result in Denial of Serivce condition.
  Impact Level: Application";
tag_affected = "Wireshark version 0.99.6 to 1.0.8, 1.2.0 to 1.2.1 on Linux";
tag_insight = "The flaw is due to unspecified error in 'OpcUa' dissector which can be
  exploited by sending malformed OPCUA Service CallRequest packets.";
tag_solution = "Upgrade to Wireshark 1.0.9 or 1.2.2
  http://www.wireshark.org/download.html";
tag_summary = "This host is installed with Wireshark and is prone to Denial of
  Service vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.901032";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-09-24 10:05:51 +0200 (Thu, 24 Sep 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-3241");
  script_bugtraq_id(36408);
  script_name("Wireshark OpcUa Dissector Denial of Service Vulnerability (Linux)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36754");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2009-06.html");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2009-05.html");
  script_xref(name : "URL" , value : "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=3986");

  script_description(desc);
  script_summary("Check for the version of Wireshark");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_lin.nasl");
  script_require_keys("Wireshark/Linux/Ver");
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
include("host_details.inc");

# Alert for Wireshark version 0.96.6 to 1.0.8 and 1.2.0 to 1.2.1
ver = get_app_version(cpe:"cpe:/a:wireshark:wireshark", nvt:SCRIPT_OID);
if(version_in_range(version:ver, test_version:"0.99.6", test_version2:"1.0.8")||
   version_in_range(version:ver, test_version:"1.2.0", test_version2:"1.2.1")){
  security_hole(0);
}
