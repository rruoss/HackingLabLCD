###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tikiwiki_xss_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# TikiWiki Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow remote attackers to inject arbitrary HTML
  codes in the context of the affected web application.
  Impact Level: Application";
tag_affected = "TikiWiki version 2.2, 2.3 and prior.";
tag_insight = "Multiple flaws are due to improper sanitization of user supplied input in
  the pages i.e. 'tiki-orphan_pages.php', 'tiki-listpages.php',
  'tiki-list_file_gallery.php' and 'tiki-galleries.php' which lets the attacker
  conduct XSS attacks inside the context of the web application.";
tag_solution = "No solution or patch is available as of 14th April, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For more info refer, http://info.tikiwiki.org";
tag_summary = "This host is running TikiWiki and is prone to Multiple Cross Site Scripting
  vulnerabilities.";

if(description)
{
  script_id(800266);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-16 16:39:16 +0200 (Thu, 16 Apr 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-1204");
  script_bugtraq_id(34105, 34106, 34107, 34108);
  script_name("TikiWiki Multiple Cross Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34273");
  script_xref(name : "URL" , value : "http://info.tikiwiki.org/tiki-read_article.php?articleId=51");

  script_description(desc);
  script_summary("Check for XSS attacks in TikiWiki");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 8080);
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

httpPort = get_kb_item("Services/www");
if(!httpPort){
  exit(0);
}

if(!safe_checks())
{
  foreach dir (make_list("/tiki", "/wiki", "/tikiwiki", cgi_dirs()))
  {
    # Multiple XSS attempts
    sndReq = http_get(item:string(dir, "/tiki-index.php"), port:httpPort);
    rcvRes = http_send_recv(port:httpPort, data:sndReq);
    if("Tikiwiki" >< rcvRes)
    {
      request = http_get(item:dir + '/tiki-listpages.php/<script>alert("XSS_Check");</script>',
                         port:httpPort);
      response = http_send_recv(port:httpPort, data:request);
      if("XSS" >< response && "Check" >< response)
      {
        security_warning(httpPort);
        exit(0);
      }
      request = http_get(item:dir + '/tiki-galleries.php/<script>alert("XSS_Check");</script>',
                         port:httpPort);
      response = http_send_recv(port:httpPort, data:request);
      if("XSS" >< response && "Check" >< response)
      {
        security_warning(httpPort);
        exit(0);
      }
      request = http_get(item:dir + '/tiki-orphan_pages.php/<script>alert("XSS_Check");</script>',
                         port:httpPort);
      response = http_send_recv(port:httpPort, data:request);
      if("XSS" >< response && "Check" >< response)
      {
        security_warning(httpPort);
        exit(0);
      }
      request = http_get(item:dir + '/tiki-list_file_gallery.php/<script>alert("XSS_Check");</script>',
                         port:httpPort);
      response = http_send_recv(port:httpPort, data:request);
      if("XSS" >< response && "Check" >< response)
      {
        security_warning(httpPort);
        exit(0);
      }
      exit(0);
    }
  }
}
