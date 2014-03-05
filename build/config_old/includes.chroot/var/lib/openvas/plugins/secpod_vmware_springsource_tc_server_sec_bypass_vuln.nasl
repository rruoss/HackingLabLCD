###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_vmware_springsource_tc_server_sec_bypass_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# SpringSource tc Server 'JMX' Interface Security Bypass Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attacker to obtain JMX interface access
  via a blank password.
  Impact Level: Application";
tag_affected = "VMware SpringSource tc Server Runtime 6.0.19 and 6.0.20 before 6.0.20.D and
  6.0.25.A before 6.0.25.A-SR01.";
tag_insight = "The flaw is cused due to error in,
  'com.springsource.tcserver.serviceability.rmi.JmxSocketListener', if the
  listener is configured to use an encrypted password then entering either the
  correct password or an empty string will allow authenticated access to the
  JMX interface.";
tag_solution = "Update to SpringSource tc Server Runtime to 6.0.20.D or 6.0.25.A-SR01,
  For updates refer to http://www.springsource.com/products/tcserver";
tag_summary = "This host is running SpringSource tc Server and is prone to security
  bypass vulnerability.";

if(description)
{
  script_id(902188);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)");
  script_cve_id("CVE-2010-1454");
  script_bugtraq_id(40205);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("SpringSource tc Server 'JMX' Interface Security Bypass Vulnerability");
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
  script_summary("Check version of SpringSource tc Server Runtime");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_vmware_springsource_tc_server_detect.nasl");
  script_require_ports("Services/www", 8080);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39778");
  script_xref(name : "URL" , value : "http://www.springsource.com/security/cve-2010-1454");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

sstcPort = get_http_port(default:8080);
if(!sstcPort){
  exit(0);
}

sstcVer = get_kb_item(string("www/", sstcPort, "/Vmware/SSTC/Runtime"));
if(isnull(sstcVer)){
  exit(0);
}

sstcVer = eregmatch(pattern:"^(.+) under (/.*)$", string:sstcVer);
if(isnull(sstcVer[1])){
  exit(0);
}

if(version_is_equal(version:sstcVer[1], test_version:"6.0.19") ||
   version_in_range(version:sstcVer[1], test_version:"6.0.20", test_version2:"6.0.20.C") ||
   version_in_range(version:sstcVer[1], test_version:"6.0.25", test_version2:"6.0.25.A.SR00")){
  security_hole(sstcPort);
}
