###############################################################################
# OpenVAS Vulnerability Test
# $Id: zervit_34530.nasl 15 2013-10-27 12:49:54Z jan $
#
# Zervit Webserver multiple vulnerabilities
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
tag_summary = "According to its version number, the remote version of Zervit HTTP
  server is prone to a remote buffer-overflow vulnerability and to a
  directory-traversal vulnerability.

  An attacker can exploit the remote buffer-overflow issue to execute
  arbitrary code within the context of the affected application.
  Failed exploit attempts will result in a denial-of-service
  condition. 

  Exploiting the directory-traversal issue will allow an attacker to
  view arbitrary local files within the context of the webserver.
  Information harvested may aid in launching further attacks.

  Zervit 0.2, 0.3 and 0.4 are vulnerable; other versions may also be
  affected.";


if (description)
{
 script_id(100199);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-05-14 12:53:07 +0200 (Thu, 14 May 2009)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_cve_id("CVE-2009-1353");
 script_bugtraq_id(34530,34570);
 script_tag(name:"risk_factor", value:"Medium");

 script_name("Zervit Webserver multiple vulnerabilities");
 desc = "

 Summary:
 " + tag_summary;


 script_description(desc);
 script_summary("Determine if Zervit is prone to multiple Vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34530");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34570");
 exit(0);
}

include("misc_func.inc");
include("http_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port)) exit(0);
if(get_kb_item("Services/www/" + port + "/embedded" ))exit(0);

banner = get_http_banner(port:port);
if (!banner)exit(0);
if(!egrep(pattern:"Server: Zervit ([0-9.]+)", string:banner) ) exit(0);

version = eregmatch(pattern: "Zervit ([0-9.]+)", string: banner);

if( version[1] =~ "0.(2|3|4)" ) {

 security_warning(port:port);
 exit(0);

}  

exit(0);
