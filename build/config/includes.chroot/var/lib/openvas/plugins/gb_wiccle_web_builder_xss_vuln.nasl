###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wiccle_web_builder_xss_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Wiccle Web Builder 'post_text' Cross-Site Scripting Vulnerability
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
tag_impact = "Successful exploitation will allow attackers to execute arbitrary web
  script or HTML in a user's browser session in the context of an affected
  site.
  Impact Level: Application";
tag_affected = "Wiccle Web Builder (WWB) Versions 1.00 and 1.0.1";
tag_insight = "The flaw is caused by improper validation of user-supplied input passed via
  the 'post_text' parameter in a site 'custom_search' action to 'index.php',
  that allows attackers to execute arbitrary HTML and script code on the web
  server.";
tag_solution = "No solution or patch is available as of 14th September, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.wiccle.com/page/download_wiccle";
tag_summary = "The host is running Wiccle Web Builder and is prone to Cross-Site
  scripting vulnerability.";

if(description)
{
  script_id(801288);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-09-15 08:47:45 +0200 (Wed, 15 Sep 2010)");
  script_cve_id("CVE-2010-3208");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Wiccle Web Builder 'post_text' Cross-Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41191");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/61466");
  script_xref(name : "URL" , value : "http://www.packetstormsecurity.com/1008-exploits/wiccle-xss.txt");

  script_description(desc);
  script_summary("Check if Wiccle Web Builder is vulnerable to Cross-Site Scripting");
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

foreach dir (make_list("/wwb", "/", cgi_dirs()))
{
  ## Send and Recieve the response
  req = http_get(item:string(dir,"/index.php?module=site&show=home"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  ## Confirm the application
  if("Powered by Wiccle - Wiccle Web Builder" >< res)
  {
    ## Construct the Attack Request
    url = dir+ "/index.php?module=site&show=post_search&post_text=%3Cmarquee" +
          "%3E%3Cfont%20color=red%20size=15%3EOpenVAS%20XSS%20Attack%3C/font" +
          "%3E%3C/marquee%3E";

    ## Try attack and check the response to confirm vulnerability.
    if(http_vuln_check(port:port, url:url, pattern:"<b><marquee><font color=" +
                       "red size=15>OpenVAS XSS Attack</font></marquee>"))
    {
      security_warning(port);
      exit(0);
    }
  }
}
