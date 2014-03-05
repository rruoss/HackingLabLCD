###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tecomat_51602.nasl 12 2013-10-27 11:15:33Z jan $
#
# Tecomat Foxtrot Default Password Security Bypass Vulnerability
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
tag_summary = "Tecomat Foxtrot is prone to a security-bypass vulnerability.

Successful attacks can allow an attacker to gain access to
the affected application using the default authentication
credentials.";


desc = "
 Summary:
 " + tag_summary;


if (description)
{
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51602");
 script_xref(name : "URL" , value : "http://dsecrg.com/pages/vul/show.php?id=407");
 script_xref(name : "URL" , value : "http://www.tecomat.com/index.php?a=cat.308");
 script_id(103397);
 script_bugtraq_id(51602);
 script_version ("$Revision: 12 $");

 script_name("Tecomat Foxtrot Default Password Security Bypass Vulnerability");

 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-01-24 10:17:53 +0100 (Tue, 24 Jan 2012)");
 script_description(desc);
 script_summary("Determine if it is possible to login with default Credentials");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

url = "/syswww/login.xml";
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if("SoftPLC" >!< buf)exit(0);

cookie = eregmatch(string:buf, pattern:"Set-Cookie: SoftPLC=([^;]+)");

if(isnull(cookie[1]))exit(0);
c = cookie[1];

host = get_host_name();

for(i=9; i>=0;i--) {

  req = string("POST ",url, " HTTP/1.1\r\n",
               "Host: ",host,"\r\n",
               "Connection: keep-alive\r\n",
               "Referer: http://",host,url,"\r\n",
               "Cookie: SoftPLC=",c,"\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: 10\r\n",
               "\r\n",
               "USER=",i,"&PASS=",i,"\r\n\r\n");

    buf = http_keepalive_send_recv(port:port, data:req);

    search = string("Location: http://",host,"/index.xml");

    if(egrep(string:buf, pattern:search)) {

      desc += string("\n\nIt was possible to login with the following credentials\n\nURL:User:Password\n\n",url,":",i,":",i,"\n");

      security_hole(port:port,data:desc);
      exit(0);

    }

    sleep(1);

}
