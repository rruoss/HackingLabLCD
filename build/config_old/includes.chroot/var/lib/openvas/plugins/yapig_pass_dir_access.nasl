# OpenVAS Vulnerability Test
# $Id: yapig_pass_dir_access.nasl 17 2013-10-27 14:01:43Z jan $
# Description: YaPiG Password Protected Directory Access Flaw
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
tag_summary = "The remote web server contains a PHP application that is prone to an
information disclosure flaw. 

Description :

The remote host is running YaPiG, a web-based image gallery written in
PHP. 

The remote version of this software contains a flaw that can let a
malicious user view images in password protected directories. 
Successful exploitation of this issue may allow an attacker to access
unauthorized images on a vulnerable server.";

tag_solution = "Unknown at this time.";

if(description)
{
 script_id(18628);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(14099);
 script_xref(name:"OSVDB", value:"11025");
 script_tag(name:"cvss_base", value:"2.0");
 script_tag(name:"cvss_base_vector", value:"AV:R/AC:H/Au:N/C:P/A:N/I:N/B:N");
 script_tag(name:"risk_factor", value:"Low");
 name = "YaPiG Password Protected Directory Access Flaw";

 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 
 summary = "Checks for YaPiG version";
 
 script_summary(summary);
 script_category(ACT_ATTACK);
 
 script_copyright("This script is Copyright (C) 2005 David Maciejak");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://sourceforge.net/tracker/index.php?func=detail&amp;aid=842990&amp;group_id=93674&amp;atid=605076");
 script_xref(name : "URL" , value : "http://sourceforge.net/tracker/index.php?func=detail&amp;aid=843736&amp;group_id=93674&amp;atid=605076");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);
if(!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


if (thorough_tests) dirs = make_list("/yapig", "/gallery", "/photos", "/photo", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
	res = http_get_cache(item:string(dir, "/"), port:port);
	if (res == NULL) exit(0);

	#Powered by <a href="http://yapig.sourceforge.net" title="Yet Another PHP Image Gallery">YaPig</a> V0.92b
 	if(egrep(pattern:"Powered by .*YaPig.* V0\.([0-8][0-9]($|[^0-9])|9([0-3]|4[a-u]))", string:res))
 	{
 		security_note(port);
		exit(0);
	}
 
}
