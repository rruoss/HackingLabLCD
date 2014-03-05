###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phd_help_desk_sql_inj_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# PHD Help Desk SQL Injection vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  commands or execute arbitrary HTML or web script in a user's browser session
  in context of an affected site.
  Impact Level: Application";

tag_affected = "PHD Help Desk version 2.12, other versions may also be affected";
tag_insight = "The application does not validate the 'operador', 'contrasenia', and 'captcha'
  parameters upon submission to the login.php script.";
tag_solution = "No solution or patch is available as of 4th June, 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.p-hd.com.ar";
tag_summary = "This host is installed with PHD Help Desk and is prone to SQL
  injection vulnerability.";

if(description)
{
  script_id(803802);
  script_version("$Revision: 11 $");
  script_bugtraq_id(60273);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-06-04 15:34:49 +0530 (Tue, 04 Jun 2013)");
  script_name("PHD Help Desk SQL Injection vulnerability");
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
  script_xref(name : "URL" , value : "http://1337day.com/exploit/20843");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/25915");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/121869/phdhelpdesk-sql.txt");
  script_xref(name : "URL" , value : "http://forelsec.blogspot.in/2013/06/phd-help-desk-212-sqli-and-xss.html");

  script_description(desc);
  script_summary("Check if PHD Help Desk is vulnerable to sql injection");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
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

## Variable Initialization
url = "";
req = "";
res = "";
port = "";
sndReq = "";
rcvRes = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  port = 80;
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Iterate over the possible directories
foreach dir (make_list("", "/phd", "/helpdesk", cgi_dirs()))
{
  ## Request for the search.cgi
  sndReq = http_get(item:string(dir, "/login.php"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:TRUE);

  ## confirm the Application
  if(rcvRes && ">PHD Help Desk" >< rcvRes && "request access<" >< rcvRes)
  {
    ## Construct the POST data
    postdata = "operador='&captcha=&contrasenia=pass&submit=Enter";

    req = string("POST ", dir, "/login.php HTTP/1.1\r\n",
                 "Host: ", get_host_name(), "\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(postdata), "\r\n",
                 "\r\n", postdata);

    res = http_keepalive_send_recv(port:port, data:req);

    ## Confirm exploit worked by checking the response
    if(res && ('You have an error in your SQL syntax;' >< res) &&
                         (res =~ "<b>Notice</b>:.*login.php"))
    {
      security_hole(port);
      exit(0);
    }
  }
}
