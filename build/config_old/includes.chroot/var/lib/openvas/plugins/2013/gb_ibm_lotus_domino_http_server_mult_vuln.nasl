###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_lotus_domino_http_server_mult_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# IBM Lotus Domino HTTP Server Multiple Vulnerabilities
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary HTML or
  web script in a user's browser session in context of an affected site,
  compromise the application and access web server configuration
  information.
  Impact Level: Application";

tag_affected = "IBM Lotus Domino 7.x and 8.x before 8.5.4";
tag_insight = "- Input appended to the URL after servlet/ is not properly sanitized before
    being returned to the user.
  - Input passed via the 'Src' parameter to MailFS and WebInteriorMailFS is not
    properly sanitized before being returned to the user.
  - Input passed via the 'RedirectTo' parameter to names.nsf?Login is not
    properly sanitized before being returned to the user.
  - The 'domcfg.nsf' page is accessible without authentication, there is a
    leakage of information about web server configuration.";
tag_solution = "Update to IBM Lotus Domino 8.5.4 or later,
  For updates refer to http://www-142.ibm.com/software/products/us/en/ibmdomino";
tag_summary = "This host is running Lotus Domino HTTP Server and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(803187);
  script_version("$Revision: 11 $");
  script_bugtraq_id(55095, 58152);
  script_cve_id("CVE-2012-3301", "CVE-2012-3302", "CVE-2012-4842", "CVE-2012-4844");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-27 14:56:20 +0530 (Wed, 27 Mar 2013)");
  script_name("IBM Lotus Domino HTTP Server Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://osvdb.org/84768");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50330");
  script_xref(name : "URL" , value : "http://securityvulns.ru/docs28474.html");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/77401");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/79233");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2012/Sep/55");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21614077");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21608160");

  script_description(desc);
  script_summary("Read the configuration information from domcfg.nsf");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
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
if(http_vuln_check(port:port, url:"/domcfg.nsf", check_header:TRUE,
   pattern:"Web Server Configuration",
   extra_check: make_list("NotesView", "_domino_name")))
{
  security_hole(port);
  exit(0);
}
