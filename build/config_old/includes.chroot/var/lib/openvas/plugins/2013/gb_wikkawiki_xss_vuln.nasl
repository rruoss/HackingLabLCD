###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wikkawiki_xss_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# WikkaWiki Cross Site Scripting Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803892";

if (description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-5586");
  script_bugtraq_id(62325);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-09-16 15:14:50 +0530 (Mon, 16 Sep 2013)");
  script_name("WikkaWiki Cross Site Scripting Vulnerability");

  tag_summary =
"This host is running WikkaWiki and is prone to cross-site scripting
vulnerability.";

  tag_vuldetect =
"Send a crafted data via HTTP GET request and check whether it is able to
read the cookie or not.";

  tag_insight =
"Input passed via 'wakka' parameter to 'wikka.php' script is not properly
sanitised before being returned to the user.";

  tag_impact =
"Successful exploitation will allow attacker to execute arbitrary HTML and
script code in a user's browser session in the context of an affected site.

Impact Level: Application";

  tag_affected =
"WikkaWiki 1.3.4 and probably prior.";

  tag_solution =
"Upgrade to WikkaWiki 1.3.4-p1 or later,
For updates refer to http://www.wikkawiki.org";

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
  script_xref(name : "URL" , value : "http://www.osvdb.com/97183");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/54790");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2013/Sep/47");
  script_xref(name : "URL" , value : "https://www.htbridge.com/advisory/HTB23170");
  script_summary("Check if WikkaWiki is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
http_port = "";
req = "";
res = "";
url = "";

## Get HTTP Port
http_port = get_http_port(default:80);
if(!http_port){
  http_port = 80;
}

## Check the port status
if(!get_port_state(http_port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:http_port)){
  exit(0);
}

foreach dir (make_list("", "/wikka", "/wiki", "/wikkawiki", cgi_dirs()))
{
  ## Confirm the Application
  if(http_vuln_check(port:http_port, url:string(dir,"/HomePage"),
                                check_header:TRUE,
                                pattern:"WikkaWiki<"))
  {
    url = dir + '/"onmouseover="javascript:alert(document.cookie)';

    ## Check the response to confirm vulnerability
    if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
       pattern:"onmouseover=.javascript:alert\(document.cookie\)",
       extra_check:make_list(">Powered by WikkaWiki<")))
    {
      security_warning(http_port);
      exit(0);
    }
  }
}
