###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_linux_rootkit_nginx_iframe_injection.nasl 12 2013-10-27 11:15:33Z jan $
#
# 64-bit Debian Linux Rootkit with nginx Doing iFrame Injection
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful iframe injection leads redirecting to some malicious sites.
  Impact Level: System/Application";
tag_affected = "64-bit Debian Squeeze (kernel version 2.6.32-5-amd64) with nginx.";
tag_insight = "64-bit Debian Squeeze Linux Rootkit in combination with nginx launching
  iframe injection attacks.";
tag_solution = "No solution or patch is available as of 3rd, December 2012. Information
  regarding this issue will be updated once the solution details are available.";
tag_summary = "The host is running Debian Squeeze Linux Rootkit with nginx and
  is prone to iframe injection.";

if(description)
{
  script_id(802045);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:N");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-12-03 13:43:19 +0530 (Mon, 03 Dec 2012)");
  script_name("64-bit Debian Linux Rootkit with nginx Doing iFrame Injection");
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
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2012/Nov/94");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2012/Nov/172");
  script_xref(name : "URL" , value : "http://blog.crowdstrike.com/2012/11/http-iframe-injecting-linux-rootkit.html");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/blog/208193935/New_64_bit_Linux_Rootkit_Doing_iFrame_Injections");

  script_description(desc);
  script_summary("Check if 64-bit Debian Squeeze Linux with nginx has Rootkit");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Malware");
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
port = 0;
banner = "";
bad_req = "";
bad_res = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Confirm the application before trying exploit
banner = get_http_banner(port: port);
if(!banner || "Server: nginx" >!< banner){
  exit(0);
}

## Construct BAD Request with wrong host header
bad_req = string( "GET / HTTP/1.1\r\n",
                  "Hostttt ", get_host_name(), "\r\n\r\n");

## Send bad request
bad_res = http_send_recv(port:port, data:bad_req);

## Check iframe is injected by the rootkit or not
if("HTTP/1.1 400 Bad Request" >< bad_res && "Server: nginx" >< bad_res &&
   egrep(pattern:"<iframe\s+src=.*</iframe>", string:bad_res, icase:TRUE)){
  security_hole(port);
}
