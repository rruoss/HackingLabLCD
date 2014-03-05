###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tcwphpalbum_mult_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# TCW PHP Album 'album' Parameter Multiple Vulnerabilities
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
tag_impact = "Successful exploitation may allow an attacker to run HTML or JavaScript code
  in the context of the affected site, or exploit latent vulnerabilities in the
  underlying database.
  Impact Level: Application";
tag_affected = "TCW PHP Album Version 1.0";
tag_insight = "The flaws are caused by improper validation of user-supplied input passed
  via the 'album' parameter to 'index.php', which allows attackers to perform
  cross-site scripting, SQL-injection, and HTML-Injection attacks.";
tag_solution = "No solution or patch is available as of 16th July, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://tcwphpalbum.sourceforge.net/";
tag_summary = "This host is running TCW PHP Album and is prone to multiple
  input validation vulnerabilities.";

if(description)
{
  script_id(801231);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-07-19 10:09:06 +0200 (Mon, 19 Jul 2010)");
  script_cve_id("CVE-2010-2714","CVE-2010-2715");
  script_bugtraq_id(41382);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("TCW PHP Album 'album' Parameter Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/60078");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/60079");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/1696");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14203");

  script_description(desc);
  script_summary("Determine if TCW PHP Album is prone to XSS Vulnerability");
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

foreach dir (make_list("/phpalbum", "/tcwphpalbum", "/", cgi_dirs() ))
{
  ## Send and Recieve the response
  req = http_get(item:string(dir,"/index.php"),  port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  ## Confirm the application
  if("<TITLE>My Pics</TITLE>" >< res && "tcwphpalbum" >< res)
  {
    ## Try XSS attack and check the response to confirm vulnerability.
    if(http_vuln_check(port:port, url:string(dir,"/index.php?album=<script>",
                       "alert('OpenVAS-XSS-Test')</script>"),
                       pattern:"<script>alert\('OpenVAS-XSS-Test'\)</script>"))
    {
      security_hole(port:port);
      exit(0);
    }
  }
}
