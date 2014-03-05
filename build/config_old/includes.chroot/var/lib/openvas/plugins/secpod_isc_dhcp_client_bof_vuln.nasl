###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_isc_dhcp_client_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# ISC DHCP Client Buffer Overflow Vulnerability
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
tag_impact = "Successful exploitation allows attackers to run arbitrary code, corrupt memory,
  and can cause denial of service.
  Impact Level: Application";
tag_affected = "ISC DHCP dhclient 4.1 before 4.1.0p1
  ISC DHCP dhclient 4.0 before 4.0.1p1
  ISC DHCP dhclient 3.1 before 3.1.2p1
  ISC DHCP dhclient all versions in 3.0
  and 2.0 series.";
tag_insight = "The flaw is due to a boundary error within the 'script_write_params()'
  function in 'client/dhclient.c' which can be exploited to cause a stack-based
  buffer overflow by sending an overly long subnet-mask option.";
tag_solution = "Upgrade to version 4.1.0p1, 4.0.1p1, or 3.1.2p1 or later
  For updates refer to https://www.isc.org/downloadables/";
tag_summary = "This host has installed ISC DHCP Client and is prone to Buffer
  overflow Vulnerability.";

if(description)
{
  script_id(900694);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-07-23 21:05:26 +0200 (Thu, 23 Jul 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-0692");
  script_bugtraq_id(35668);
  script_name("ISC DHCP Client Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "https://www.isc.org/node/468");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35785");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/410676");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/1891");

  script_description(desc);
  script_summary("Checks for the version of ISC DHCP Client");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_isc_dhcp_client_detect.nasl");
  script_require_keys("ISC/DHCP-Client/Ver");
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

dhcpVer = get_kb_item("ISC/DHCP-Client/Ver");
if(!dhcpVer){
  exit(0);
}

if(dhcpVer =~ "^4\.1")
{
  if(version_is_less(version:dhcpVer, test_version:"4.1.0.p1")){
    security_hole(0);
  }
}

else if(dhcpVer =~ "^4\.0")
{
  if(version_is_less(version:dhcpVer, test_version:"4.0.1.p1")){
    security_hole(0);
  }
}

else if(dhcpVer =~ "^3\.1")
{
  if(version_is_less(version:dhcpVer, test_version:"3.1.2.p1")){
    security_hole(0);
  }
}

else if((dhcpVer =~ "^3\.0") || (dhcpVer =~ "^2\.0")){
  security_hole(0);
}
