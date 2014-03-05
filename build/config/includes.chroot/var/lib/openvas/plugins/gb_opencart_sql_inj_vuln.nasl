##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opencart_sql_inj_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# OpenCart SQL Injection Vulnerability
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary SQL
  statements on the vulnerable system, which may leads to access or modify data,
  or exploit latent vulnerabilities in the underlying database.
  Impact Level: Application.";
tag_affected = "OpenCart version 1.3.2";

tag_insight = "The flaw exists in 'index.php' as it fails to sanitize user-supplied data
  before using it in an SQL query. Remote attackers could exploit this to
  execute arbitrary SQL commands via the page parameter.";
tag_solution = "No solution or patch is available as of 12th March 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.opencart.com/";
tag_summary = "This host is running OpenCart and is prone to SQL Injection
  vulnerability.";

if(description)
{
  script_id(800734);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-03-18 15:44:57 +0100 (Thu, 18 Mar 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_bugtraq_id(38605);
  script_cve_id("CVE-2010-0956");
  script_name("OpenCart SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/1003-exploits/opencart-sql.txt");

  script_description(desc);
  script_summary("Check through the attack string");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("http_func.inc");

## Get HTTP port
openPort = get_http_port(default:80);
if(!openPort){
  exit(0);
}

## Check for the exploit on OpenCart
foreach dir (make_list("/opencart", "/" , cgi_dirs()))
{
  sndReq = http_get(item:string(dir, "/index.php"), port:openPort);
  rcvRes = http_send_recv(port:openPort, data:sndReq);

  if(rcvRes =~ "[Pp]owered [Bb]y [Oo]penCart")
  {
    ## Send an exploit and recieve the response
    sndReq = http_get(item:string(dir, "/index.php?route=product/special&path" +
                                      "=20&page='"), port:openPort);
    rcvRes = http_send_recv(port:openPort, data:sndReq);

    ## Check the response for SQL statements
    if(("SELECT *" >< rcvRes && "ORDER BY" >< rcvRes))
    {
      security_hole(openPort);
      exit(0);
    }
  }
}
