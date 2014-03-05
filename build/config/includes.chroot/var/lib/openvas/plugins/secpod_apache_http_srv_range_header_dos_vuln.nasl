###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apache_http_srv_range_header_dos_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Apache httpd Web Server Range Header Denial of Service Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will let the remote unauthenticated attackers to
  cause a denial of service.
  Impact Level: System/Application";
tag_affected = "Apache 1.3.x, 2.0.x through 2.0.64 and 2.2.x through 2.2.19";
tag_insight = "The flaw is caused the way Apache httpd web server handles certain requests
  with multiple overlapping ranges, which causes significant memory and CPU
  usage on the server leading to application crash and system can become
  unstable.";
tag_solution = "Please refer below link for fix and mitigate this issue until full fix,
  http://mail-archives.apache.org/mod_mbox/httpd-dev/201108.mbox/%3CCAAPSnn2PO-d-C4nQt_TES2RRWiZr7urefhTKPWBC1b+K1Dqc7g@mail.gmail.com%3E
  http://marc.info/?l=apache-httpd-dev&m=131420013520206&w=2";
tag_summary = "This host is running Apache httpd web server and is prone to denial
  of service vulnerability.";

if(description)
{
  script_id(901203);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-26 14:59:42 +0200 (Fri, 26 Aug 2011)");
  script_bugtraq_id(49303);
  script_cve_id("CVE-2011-3192");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_name("Apache httpd Web Server Range Header Denial of Service Vulnerability");
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
  script_summary("Check Apache httpd web server is vulnerable to Range Header Attack");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17696");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/104441");
  script_xref(name : "URL" , value : "http://marc.info/?l=apache-httpd-dev&amp;m=131420013520206&amp;w=2");
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

## Get Host Name or IP
host = get_host_name();
if(!host){
  exit(0);
}

## Confirm the application before trying exploit
banner = get_http_banner(port: port);
if("Server: Apache" >!< banner) {
  exit(0);
}

## Construct Valid Range Request
## Expected response will be 206 Partial Content on both
req1 = string("HEAD / HTTP/1.1\r\n",
              "Host: ", host, "\r\n",
              "User-Agent: Apache Range Header Agent\r\n",
              "Accept-Encoding: gzip\r\n",
              "Range: bytes=0-100\r\n",
              "Connection: close\r\n",
              "\r\n" );

## Construct Range bytes
range_bytes = "";
for (i = 0; i < 30; i++){
  range_bytes += "5-" + i;
  if(i < 29) range_bytes += ",";
}

## Construct Invalid Range Request
## Expected response will be 200 OK on non vulnerable
## Expected response will be 206 Partial Content on vulnerable
req2 = string("HEAD / HTTP/1.1\r\n",
              "Host: ", host, "\r\n",
              "User-Agent: Apache Range Header Agent\r\n",
              "Accept-Encoding: gzip\r\n",
              "Range: bytes=" + range_bytes + "\r\n",
              "Connection: close\r\n",
              "\r\n" );

## Send and Receive the response
res1 = http_send_recv(port:port, data:req1);
res2 = http_send_recv(port:port, data:req2);

## Check Server response to verify is it vulnerable
if(res1 =~ "HTTP\/[0-9]\.[0-9] 206 Partial Content" &&
   res2 =~ "HTTP\/[0-9]\.[0-9] 206 Partial Content"){
  security_hole(port);
}
