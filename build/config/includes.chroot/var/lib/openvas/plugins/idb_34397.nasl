###############################################################################
# OpenVAS Vulnerability Test
# $Id: idb_34397.nasl 15 2013-10-27 12:49:54Z jan $
#
# iDB 'skin' Parameter Local File Include Vulnerability
#
# Authors
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
tag_summary = "iDB (Internet Discussion Boards) is prone to a local file-include
  vulnerability because it fails to properly sanitize user-supplied
  input.

  An attacker can exploit this vulnerability to view and execute
  arbitrary local files in the context of the webserver process. This
  may aid in further attacks.

  iDB 0.2.5 Pre-Alpha SVN 243 is vulnerable; other versions may also
  be affected.";


if (description)
{
 script_id(100110);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-04-07 09:57:50 +0200 (Tue, 07 Apr 2009)");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2009-1498");
 script_bugtraq_id(34397);
 script_tag(name:"risk_factor", value:"High");

 script_name("iDB 'skin' Parameter Local File Include Vulnerability");
 desc = "

 Summary:
 " + tag_summary;


 script_description(desc);
 script_summary("Determine if iDB vulnerable to Local File Include");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("idb_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34397");
 exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if(!version = get_kb_item(string("www/", port, "/iDB")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];

if(!isnull(vers) && vers >!< "unknown") {

  if(ereg(pattern: "^0.2.5 SVN 243$", string: vers)) {
   security_hole(port:port);
   exit(0);
  }  
}   

exit(0);
