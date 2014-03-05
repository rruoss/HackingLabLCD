###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_lotus_domino_mult_info_disc_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# IBM Lotus Domino Multiple Information Disclosure Vulnerabilities
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

if(description)
{
  script_id(803755);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-09-04 16:22:08 +0530 (Wed, 04 Sep 2013)");
  script_name("IBM Lotus Domino Multiple Information Disclosure Vulnerabilities");

  tag_summary =
"This host is running Lotus Domino Server and is prone to multiple information
disclosure vulnerabilities.";

  tag_vuldetect =
"Send the direct HTTP request to restricted config files and check it is
possible to read the configuration file content or not.";

  tag_insight =
"The flaws are due to the multiple config files (names.nsf, admin4.nsf,
catalog.nsf, events4.nsf) are accessible without authentication, there
is a leakage of information about web server configuration.";

  tag_impact =
"Successful exploitation will allow attacker to access web server
configuration information.

Impact Level: Application";

  tag_affected =
"IBM Lotus Domino 8.5.3, 8.5.4, 9.0 and previous versions.";

  tag_solution =
"No solution or patch is available as of 04th, September 2013. Information
regarding this issue will be updated once the solution details are available.
For updates refer to http://www.cisco.com/en/US/products/ps12503/index.html ";

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
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "impact" , value : tag_impact);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://websecurity.com.ua/5829");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2013/Apr/248");
  script_summary("Read the user information from names.nsf");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
port = "";
banner = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  port = 80;
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

## Confirm the application before trying exploit
banner = get_http_banner(port:port);
if("Server: Lotus-Domino" >!< banner){
  exit(0);
}

## Try attack and check the response to confirm vulnerability
if(http_vuln_check(port:port, url:"/names.nsf", check_header:TRUE,
   pattern:"_domino_name",
   extra_check: make_list("_wMainFrameset", "OpenPage")))
{
  security_hole(port);
  exit(0);
}
