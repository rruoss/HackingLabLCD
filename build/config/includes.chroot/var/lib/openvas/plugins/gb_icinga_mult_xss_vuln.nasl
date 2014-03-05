###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_icinga_mult_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Icinga Multiple Cross-Site Scripting Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_affected = "Icinga versions 1.3.0 and prior.";
tag_insight = "- Input appended to the URL after 'cgi-bin/status.cgi' and
    'cgi-bin/notifications.cgi' is not properly sanitised before being returned
    to the user.
  - Input passed via the 'layer' parameter to 'cgi-bin/statusmap.cgi' is not
    properly sanitised before being returned to the user.";
tag_solution = "No solution or patch is available as of 15th March, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.icinga.org/download/";
tag_summary = "This host is running Icinga and is prone to multiple cross site
  scripting vulnerabilities.";

if(description)
{
  script_id(801866);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-03-16 15:16:52 +0100 (Wed, 16 Mar 2011)");
  script_bugtraq_id(46788);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Icinga Multiple Cross-Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43643");
  script_xref(name : "URL" , value : "http://www.rul3z.de/advisories/SSCHADV2011-001.txt");
  script_xref(name : "URL" , value : "http://www.rul3z.de/advisories/SSCHADV2011-003.txt");

  script_description(desc);
  script_summary("Check if Icinga is vulnerable to Cross-Site Scripting");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("http_version.nasl");
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

foreach dir (make_list("/icinga", cgi_dirs()))
{
  ## Send and Recieve the response
  req = http_get(item:string(dir,"/main.html"),  port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  ## Confirm the application
  if("<TITLE>Icinga</TITLE>" >< res)
  {
    ## Construct attack request
    url = dir + "/cgi-bin/statusmap.cgi?layer=%27%20onmouseover=%22alert" +
                "(%27openvas-xss-test%27)%22";

    ## Try XSS and check the response to confirm vulnerability
    if(http_vuln_check(port:port, url:url, check_header: TRUE,
                       pattern:"alert\('openvas-xss-test'\)"))
    {
      security_warning(port);
      exit(0);
    }
  }
}
