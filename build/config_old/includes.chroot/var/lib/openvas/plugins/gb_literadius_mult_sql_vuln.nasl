###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_literadius_mult_sql_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# LiteRadius Multiple SQL Injection Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to obtain sensitive information
  by injecting arbitrary SQL code.
  Impact Level: Application";
tag_affected = "LiteRadius version 3.2 and prior.";
tag_insight = "The flaws are caused by improper validation of user-supplied input via the
  'lat' and 'long' parameters in 'locator.php', which allows attackers to
  manipulate SQL queries by injecting arbitrary SQL code.";
tag_solution = "No solution or patch is available as of 14th July, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.escaperadius.com/er/products/literadius/lr.php#install";
tag_summary = "The host is running LiteRadius and is prone to multiple SQL
  injection vulnerabilities.";

if(description)
{
  script_id(802121);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-15 12:23:42 +0200 (Fri, 15 Jul 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("LiteRadius Multiple SQL Injection Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17528/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/103018/literadius-sql.txt");

  script_description(desc);
  script_summary("Determine if LiteRadius is prone to SQL Injection Vulnerability");
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

foreach dir (make_list("/dealers", "/literadius", "/", cgi_dirs()))
{
  ## Send and Receive the response
  req = http_get(item: string (dir, "/index.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  ## Confirm the application
  if('<title>Dealer Locator' >< res || '<title>LiteRadius' >< res)
  {
    ## Try SQL injection and check the response to confirm vulnerability
    sndReq = http_get(item:string(dir, "/locator.php?parsed_page=1&lat=25.4405"+
                                  "436315&long=132.710253334'"), port:port);
    rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

    ## Confirm the exploit
    if(("failed SELECT sqrt(power" >< rcvRes) && ("* FROM" >< rcvRes))
    {
      security_hole(port:port);
      exit(0);
    }
  }
}
