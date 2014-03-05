###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sun_java_sys_web_serv_mult_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Sun Java System Web Server Multiple Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation lets the attackers to discover process memory
locations or execute arbitrary code in the context of an affected system
or cause the application to crash via a long URI in an HTTP OPTIONS request.
Impact Level: System/Application";
tag_affected = "Sun Java System Web Server 7.0 Update 7 and prior.";
tag_insight = "- An error exists in WebDAV implementation in webservd and can be exploited
  to cause Stack-based buffer overflow via long URI in an HTTP OPTIONS
  request.
- An unspecified error that can be exploited to cause a heap-based buffer
  overflow which allows remote attackers to discover process memory
  locations and execute arbitrary code by sending a process memory address
  via crafted data.
- Format string vulnerability in the WebDAV implementation in webservd that
  can be exploited to cause denial of service via format string specifiers
  in the encoding attribute of the XML declaration in a PROPFIND request.
- An unspecified error in admin server that can be exploited to cause
  denial of service via an HTTP request that lacks a method token.";
tag_solution = "No solution or patch is available as of 29th January, 2010. Information
regarding this issue will be updated once the solution details are available.
For updates refer to http://www.sun.com/";
tag_summary = "This host has Sun Java Web Server running which is prone to
Multiple Vulnerabilities.";

if (description)
{
 script_id(100567);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-04-12 18:40:45 +0200 (Mon, 12 Apr 2010)");
 script_bugtraq_id(37874,37910);
 script_cve_id("CVE-2010-0272","CVE-2010-0273", "CVE-2010-0360",
	       "CVE-2010-0361","CVE-2010-0388", "CVE-2010-0389");

 script_name("Sun Java System Web Server Multiple Vulnerabilities");

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
 script_xref(name : "URL" , value : "http://intevydis.com/sjws_demo.html");
 script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/55812");
 script_xref(name : "URL" , value : "http://intevydis.blogspot.com/2010/01/sun-java-system-web-server-70-admin.html");
 script_xref(name : "URL" , value : "http://intevydis.blogspot.com/2010/01/sun-java-system-web-server-70-webdav.html");
 script_xref(name : "URL" , value : "http://intevydis.blogspot.com/2010/01/sun-java-system-web-server-70u7-trace.html");
 script_xref(name : "URL" , value : "http://intevydis.blogspot.com/2010/01/sun-java-system-web-server-70u7-webdav.html");

script_tag(name:"cvss_base", value:"10.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_tag(name:"risk_factor", value:"Critical");
script_description(desc);
script_summary("Check for the version of Java System Web Server");
script_category(ACT_GATHER_INFO);
script_family("Buffer overflow");
script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
script_dependencies("gb_sun_java_sys_web_serv_detect.nasl");
script_require_ports("Services/www", 8989);
script_require_keys("Sun/Java/SysWebServ/Ver","Sun/JavaSysWebServ/Port");
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
include("version_func.inc");

if( get_kb_item("Sun/JavaSysWebServ/Ver") != "7.0"){
  exit(0);
}

port = get_http_port(default:8989);
if(!get_port_state(port))exit(0);

if(version = get_kb_item(string("Sun/JavaSysWebServ/",port,"/Ver"))) {

vers = str_replace(find:"U", string: version, replace:".");

  if(version_is_less_equal(version: vers, test_version: "7.0.7")) {
      security_hole(port:port);
      set_kb_item(name: "Sun/JavaSysWebServ/37874", value: TRUE);
      exit(0);
  }

}

exit(0);
