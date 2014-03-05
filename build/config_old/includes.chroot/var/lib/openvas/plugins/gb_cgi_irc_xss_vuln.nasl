###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cgi_irc_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# CGI:IRC 'nonjs' Interface Cross Site Scripting Vulnerability
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
tag_affected = "CGI:IRC versions prior to 0.5.10.";
tag_insight = "The flaw is caused by improper validation of user-supplied input passed via
  the 'R' parameter in the 'nonjs' interface (interfaces/nonjs.pm), that
  allows attackers to execute arbitrary HTML and script code on the web server.";
tag_solution = "Upgrade to CGI:IRC version 0.5.10 or later,
  For updates refer to http://cgiirc.org/download/";
tag_summary = "This host is running CGI:IRC and is prone to cross site scripting
  vulnerability.";

if(description)
{
  script_id(801859);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-03-10 13:33:28 +0100 (Thu, 10 Mar 2011)");
  script_cve_id("CVE-2011-0050");
  script_bugtraq_id(46303);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("CGI:IRC 'nonjs' Interface Cross Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/70844");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43217");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0346");

  script_description(desc);
  script_summary("Check if CGI:IRC is vulnerable to Cross-Site Scripting");
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
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

foreach dir (make_list("/cgiirc", cgi_dirs()))
{
  ## Send and Recieve the response
  req = http_get(item:string(dir,"/irc.cgi"),  port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  ## Confirm the application
  if(">CGI:IRC Login<" >< res)
  {
    ## Construct attack request
    url = dir + "/irc.cgi?nick=openvas&interface=mozilla&R=<script>alert" +
                "('openvas-xss-test')</script>&item=fwindowlist";

    ## Try XSS and check the response to confirm vulnerability
    if(http_vuln_check(port:port, url:url, check_header: TRUE,
                       pattern:"<script>alert\('openvas-xss-test'\)</script>"))
    {
      security_warning(port);
      exit(0);
    }
  }
}
