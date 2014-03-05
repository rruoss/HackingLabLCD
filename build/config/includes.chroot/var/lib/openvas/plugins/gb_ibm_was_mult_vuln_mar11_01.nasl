###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_was_mult_vuln_mar11_01.nasl 13 2013-10-27 12:16:33Z jan $
#
# IBM WebSphere Application Server (WAS) Multiple Vulnerabilities 01 - March 2011
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation will let attackers to obtain sensitive information
  and cause a denial of service.
  Impact Level: Application";
tag_affected = "IBM WebSphere Application Server versions 6.1.0.x before 6.1.0.35 and
  7.x before 7.0.0.15";
tag_insight = "- The Administrative Scripting Tools component, when tracing is enabled,
    places wsadmin command parameters into the 'wsadmin.traceout' and
    'trace.log' files, which allows local users to obtain potentially
    sensitive information by reading these files.
  - A double free error which allows remote backend IIOP servers to cause a
    denial of service by rejecting IIOP requests at opportunistic time
    instants.
  - The Security component allows remote authenticated users to cause a denial
    of service by using a Lightweight Third-Party Authentication (LTPA) token
    for authentication.
  - The Security component does not properly delete AuthCache entries upon a
    logout, which might allow remote attackers to access the server by
    leveraging an unattended workstation.";
tag_solution = "Upgrade to IBM WebSphere Application Server version 6.1.0.35 or 7.0.0.15,
  http://www-01.ibm.com/support/docview.wss?uid=swg24028405
  http://www-01.ibm.com/support/docview.wss?uid=swg24028875";
tag_summary = "The host is running IBM WebSphere Application Server and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(801862);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-03-22 08:43:18 +0100 (Tue, 22 Mar 2011)");
  script_cve_id("CVE-2011-1310", "CVE-2011-1313", "CVE-2011-1319", "CVE-2011-1320");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("IBM WebSphere Application Server (WAS) Multiple Vulnerabilities 01 - March 2011");
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
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg27014463");

  script_description(desc);
  script_summary("Check for the version of IBM WebSphere Application Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!get_port_state(port)){
  exit(0);
}

## Get Version from KB
vers = get_kb_item(string("www/", port, "/websphere_application_server"));
if(isnull(vers)){
  exit(0);
}

## Check for IBM WebSphere Application Server versions
if(version_in_range(version: vers, test_version: "6.1", test_version2: "6.1.0.34") ||
   version_in_range(version: vers, test_version: "7.0", test_version2: "7.0.0.14")) {
  security_hole(port:port);
}
