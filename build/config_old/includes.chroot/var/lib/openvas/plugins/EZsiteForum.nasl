# OpenVAS Vulnerability Test
# $Id: EZsiteForum.nasl 17 2013-10-27 14:01:43Z jan $
# Description: EZsite Forum Discloses Passwords to Remote Users
#
# Authors:
# deepquest <deepquest@code511.com>
#
# Copyright:
# Copyright (C) 2003 deepquest
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
tag_summary = "The remote host is running EZsite Forum.

It is reported that this software stores usernames and passwords in
plaintext form in the 'Database/EZsiteForum.mdb' file. A remote user
can reportedly download this database.";

tag_solution = "No solution was available at the time. Configure your web server
to disallow the download of .mdb files.";

#  Date: 4 sep , 2003  7:07:39  AM
#  From: cyber_talon <cyber_talon@hotmail.com>
#  Subject: EZsite Forum Discloses Passwords to Remote Users

if(description)
{
 script_id(11833);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 name = "EZsite Forum Discloses Passwords to Remote Users";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Checks for EZsiteForum.mdb password database";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("This script is Copyright (C) 2003 deepquest");
 family = "Web application abuses";
 script_family(family);
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


sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);

dirs = make_list(cgi_dirs());

foreach d (dirs)
{
 req = http_get(item:string(d, "/forum/Database/EZsiteForum.mdb"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 
 if ( res == NULL ) exit(0);
 
 if("Standard Jet DB" >< res)
	{
 	 security_warning(port);
	 exit(0);
	 }
}
