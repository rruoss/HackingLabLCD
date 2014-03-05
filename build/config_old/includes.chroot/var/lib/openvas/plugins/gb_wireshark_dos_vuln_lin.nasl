###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_dos_vuln_lin.nasl 13 2013-10-27 12:16:33Z jan $
#
# Wireshark Denial of Service Vulnerability (Linux)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation could allow attackers to cause a denial of
  service, execution of arbitrary code.
  Impact Level: Application";
tag_affected = "Wireshark version 1.4.3 and prior
  Wireshark version 1.5.0";
tag_insight = "The flaw is due to uninitialized pointer during processing of a '.pcap'
  file in the pcap-ng format.";
tag_solution = "No solution or patch is available as of 11th February 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.wireshark.org/download.html";
tag_summary = "The host is installed Wireshark and is prone to Denial of Service
  Vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801743";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-02-15 08:14:35 +0100 (Tue, 15 Feb 2011)");
  script_cve_id("CVE-2011-0538");
  script_bugtraq_id(46167);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Wireshark Denial of Service Vulnerability (Linux)");
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
  script_xref(name : "URL" , value : "http://openwall.com/lists/oss-security/2011/02/04/1");
  script_xref(name : "URL" , value : "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=5652");

  script_description(desc);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_summary("Check the version of Wireshark");
  script_category(ACT_GATHER_INFO);
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

## Check for Wireshark Version
ver = get_app_version(cpe:"cpe:/a:wireshark:wireshark", nvt:SCRIPT_OID);
if(version_is_less_equal(version:ver, test_version:"1.4.3")||
   version_is_equal(version:ver, test_version:"1.5.0")){
  security_hole(0);
}
