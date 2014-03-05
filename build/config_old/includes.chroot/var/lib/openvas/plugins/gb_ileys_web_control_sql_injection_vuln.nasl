###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ileys_web_control_sql_injection_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Ileys Web Control SQL Injection Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to cause SQL injection attack
  and gain sensitive information.
  Impact Level: Application";
tag_affected = "Ileys Web Control version 2.0";
tag_insight = "The flaw is caused by improper validation of user-supplied input passed via
  the 'id' parameter in 'view.php', which allows attacker to manipulate SQL
  queries by injecting arbitrary SQL code.";
tag_solution = "No solution or patch is available as of 04th August, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://ileystechnology.com/index.php";
tag_summary = "This host is running Ileys Web Control and is prone to sql
  injection vulnerability.";

if(description)
{
  script_id(802315);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-05 09:04:20 +0200 (Fri, 05 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Ileys Web Control SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://cryptr.org/printthread.php?tid=2278");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/103372/ileys-sql.txt");

  script_description(desc);
  script_summary("Check if Ileys Web Control is prone to SQL injection vulnerability");
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
include("version_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!get_port_state(port)) {
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)) {
  exit(0);
}

foreach dir(make_list("", "/ileys", "/admin", cgi_dirs()))
{
  ## Send and Receive the response
  sndReq = http_get (item: string(dir, "/index.php"), port:port);
  rcvRes = http_keepalive_send_recv(port:port,data:sndReq);

  ## Confirm the application
  if("Powered by:" >< rcvRes && "Ileys Web Control" >< rcvRes)
  {
    ## Construct the exploit request
    sndReq = http_get(item:string(dir, '/view.php?id=3333"'), port:port);
    rcvRes = http_send_recv(port:port, data:sndReq);

    ## Check the source code of the function in response
    if("You have an error in your SQL syntax;">< rcvRes)
    {
      security_hole(port);
      exit(0);
    }
  }
}
