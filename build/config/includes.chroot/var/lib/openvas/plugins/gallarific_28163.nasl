###############################################################################
# OpenVAS Vulnerability Test
# $Id: gallarific_28163.nasl 15 2013-10-27 12:49:54Z jan $
#
# Gallarific Cross Site Scripting and Authentication Bypass Vulnerabilities
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
tag_summary = "Gallarific is prone to a cross-site scripting vulnerability and
multiple authentication-bypass vulnerabilities.

An attacker may leverage these issues to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site, steal cookie-based authentication credentials, add new
categories, add new users, and modify existing users. Other attacks
are also possible.

These issues affect both the commercial and the free versions of
Gallarific.";

tag_solution = "Updates are available. Please contact the vendor for details.";

if (description)
{
 script_id(100309);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-10-20 18:54:22 +0200 (Tue, 20 Oct 2009)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_cve_id("CVE-2008-1326");
 script_bugtraq_id(28163);
 script_tag(name:"risk_factor", value:"Medium");

 script_name("Gallarific Cross Site Scripting and Authentication Bypass Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/28163");
 script_xref(name : "URL" , value : "http://www.gallarific.com/download.php");

 script_description(desc);
 script_summary("Determine if Gallarific is prone to multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
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
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/photos","/gallery",cgi_dirs());

foreach dir (dirs) {
   
  url =  string(dir,'/search.php?dosearch=true&query="><script>alert(document.cookie)</script>'); 
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);  
  if( buf == NULL )continue;

  if(egrep(pattern: "<script>alert\(document\.cookie\)</script>", string: buf, icase: TRUE)) {
     
    security_warning(port:port);
    exit(0);

  }
}

exit(0);

