##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpkick_sql_inj_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# PHPKick 'statistics.php' SQL Injection Vulnerability
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
tag_impact = "Successful exploitation will allow attacker to view, add, modify or
  delete information in the back-end database.
  Impact Level: Application.";
tag_affected = "PHPKick version 0.8";

tag_insight = "The flaw exists due to an error in 'statistics.php', which fails to properly
  sanitise input data passed via the 'gameday' parameter in overview action.";
tag_solution = "No solution or patch is available as of 18th, August 2010. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://www.computerclub.theeagle.de/load/";
tag_summary = "This host is running PHPKick and is prone SQL injection
  vulnerability.";

if(description)
{
  script_id(801431);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-08-19 10:23:11 +0200 (Thu, 19 Aug 2010)");
  script_cve_id("CVE-2010-3029");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("PHPKick 'statistics.php' SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14578/");
  script_xref(name : "URL" , value : "http://securityreason.com/exploitalert/8639");

  script_description(desc);
  script_summary("Check PHPKick is vulnerable to SQL Injection");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
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

## Get HTTP Port
phpPort = get_http_port(default:80);
if(!phpPort){
  exit(0);
}

foreach dir (make_list("/phpkick", "/PHPKick", "/", cgi_dirs()))
{
  ## Send and Recieve request
  sndReq = http_get(item:string(dir, "/index.php"), port:phpPort);
  rcvRes = http_send_recv(port:phpPort, data:sndReq);

  ## Confirm application is PHPKick
  if("<TITLE>PHPKick</TITLE>" >< rcvRes)
  {
    ## Try exploit and check response to confirm vulnerability
    sndReq = http_get(item:string(dir, "/statistics.php?action=overview" +
                           "&gameday=,"), port:phpPort);
    rcvRes = http_send_recv(port:phpPort, data:sndReq);

    if("SQL syntax;" >< rcvRes && "MySQL server" >< rcvRes)
    {
      security_hole(phpPort);
      exit(0);
    }
  }
}
