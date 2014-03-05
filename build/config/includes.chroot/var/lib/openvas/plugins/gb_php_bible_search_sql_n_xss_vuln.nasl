###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_bible_search_sql_n_xss_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# PHP Bible Search 'bible.php' SQL Injection and Cross Site Scripting Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation could allow the attackers to view, add, modify or
  delete information in the back-end database amd to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.
  Impact Level: Application";
tag_affected = "PHP Bible Search version 0.99";
tag_insight = "Input passed to the 'chapter' parameter in 'bible.php' script is not
  properly sanitised before being returned to the user.";
tag_solution = "No solution or patch is available as of 8th July, 2010. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://phpbiblesearch.sourceforge.net/";
tag_summary = "The host is running PHP Bible Search and is prone to SQL injection
  and cross site scripting vulnerabilities.";

if(description)
{
  script_id(801401);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-07-12 09:42:32 +0200 (Mon, 12 Jul 2010)");
  script_cve_id("CVE-2010-2616", "CVE-2010-2617");
  script_bugtraq_id(41197);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("PHP Bible Search 'bible.php' SQL Injection and Cross Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/59842");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/59843");
  script_xref(name : "URL" , value : "http://www.packetstormsecurity.com/1006-exploits/phpbiblesearch-sqlxss.txt");

  script_description(desc);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_summary("Check the exploit on PHP Bible Search to confirm vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
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

## Get HTTP Port
phpPort = get_http_port(default:80);
if(!phpPort){
  exit(0);
}

foreach dir (make_list("/phpbiblesearch", "/" , cgi_dirs()))
{
  ## Send and Recieve request
  sndReq = http_get(item:string(dir, "/bible.php"), port:phpPort);
  rcvRes = http_send_recv(port:phpPort, data:sndReq);

  ## Confirm application is PHP Bible Search
  if(">PHP Bible Search ::<" >< rcvRes)
  {
    ## Try XSS attack on PHP Bible Search application
    sndReq = http_get(item:string(dir, "/bible.php?string=&book=2&chapter=" +
                        "<script>alert('OpenVAS-XSS-Testing')</script>"), port:phpPort);
    rcvRes = http_send_recv(port:phpPort, data:sndReq);
    if(("OpenVAS-XSS-Testing" >< rcvRes))
    {
      security_hole(phpPort);
      exit(0);
    }
  }
}

