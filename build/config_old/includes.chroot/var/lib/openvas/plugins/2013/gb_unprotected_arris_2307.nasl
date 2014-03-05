###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_unprotected_arris_2307.nasl 11 2013-10-27 10:12:02Z jan $
#
# ARRIS 2307 Unprotected Web Console
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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
tag_summary = "The remote ARRIS 2307 Web Console is not protected by a password.";


tag_solution = "Set a password.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103703";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 11 $");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_name("ARRIS 2307 Unprotected Web Console");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name:"URL" , value: "http://www.arrisi.com/");

 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-04-23 12:01:48 +0100 (Tue, 23 Apr 2013)");
 script_description(desc);
 script_summary("Determine if ARRIS 2307 Web Console is protected by a password");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);
if(!get_port_state(port))exit(0);
                                                                  
url = '/login.html';

if(http_vuln_check(port:port, url:url,pattern:'content="ARRIS 2307"')) {

  host = get_host_name();
  login = "page=&logout=&action=submit&pws=";
  len = strlen(login);  

  req = string("POST /login.cgi HTTP/1.1\r\n",
               "Host: ", host,"\r\n",
               "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:17.0) Gecko/17.0 Firefox/17.0 OpenVAS\r\n",
               "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
               "Accept-Language: de-de,de;q=0.8,en-us;q=0.5,en;q=0.3\r\n",
               "Accept-Encoding: identity\r\n",
               "DNT: 1\r\n",
               "Connection: keep-alive\r\n",
               "Referer: http://",host,"/login.html\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", len,"\r\n",
               "\r\n",
               login);

  result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

  if("lan_ipaddr" >< result && "http_passwd" >< result && "userNewPswd" >< result) {
    security_hole(port:port);
    exit(0);
  }  

  exit(99);

}  

exit(0);
