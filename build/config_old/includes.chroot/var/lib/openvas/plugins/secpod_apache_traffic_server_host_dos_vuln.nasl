###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apache_traffic_server_host_dos_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Apache Traffic Server HTTP Host Header Denial of Service Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation may allow remote attackers to cause the application
  to crash, creating a denial of service condition.
  Impact Level: System/Application";
tag_affected = "Apache Traffic Server 2.0.x, 3.0.x before 3.0.4, 3.1.x before 3.1.3";
tag_insight = "The flaw is due to an improper allocation of heap memory when
  processing  HTTP request with a large 'HOST' header value and can be
  exploited to cause a denial of service via a specially crafted packet.";
tag_solution = "Upgrade to Apache Traffic Server 3.0.4 or 3.1.3 or later,
  For updates refer to http://trafficserver.apache.org/downloads";
tag_summary = "This host is running Apache Traffic Server and is prone to denial
  of service vulnerability.";

if(description)
{
  script_id(902664);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-0256");
  script_bugtraq_id(52696);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-03-28 13:46:18 +0530 (Wed, 28 Mar 2012)");
  script_name("Apache Traffic Server HTTP Host Header Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1026847");
  script_xref(name : "URL" , value : "https://secunia.com/advisories/48509/");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2012/Mar/117");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2012/Mar/260");
  script_xref(name : "URL" , value : "https://www.cert.fi/en/reports/2012/vulnerability612884.html");
  script_xref(name : "URL" , value : "http://mail-archives.apache.org/mod_mbox/www-announce/201203.mbox/%3C4F6B6649.9000507@apache.org%3E");

  script_description(desc);
  script_summary("Check for the version of Apache Traffic Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_apache_traffic_detect.nasl");
  script_require_ports("Services/http_proxy", 8080, 3128);
  script_require_keys("apache_trafficserver/installed");
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

## Variable Initialization
port = "";
atsVer = "";

##Get the Port
port = get_kb_item("Services/http_proxy");
if(!port){
  port = 8080;
}

if(!get_port_state(port)){
  exit(0);
}

##Get the version from kb
atsVer = get_kb_item("www/" + port + "/apache_traffic_server");
if(!atsVer){
  exit(0);
}

## Check for versions 2.0.x, 3.x before 3.0.4, 3.1 before 3.1.3
if(version_in_range(version:atsVer, test_version:"2.0", test_version2:"2.0.9")||
   version_in_range(version:atsVer, test_version:"3.0", test_version2:"3.0.3")||
   version_in_range(version:atsVer, test_version:"3.1", test_version2:"3.1.2")){
  security_warning(port);
}
