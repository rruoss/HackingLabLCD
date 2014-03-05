# OpenVAS Vulnerability Test
# $Id: trendmicro_emanager.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Trend Micro Emanager software check
#
# Authors:
# John Lampe <j_lampe@bellsouth.net>
#
# Copyright:
# Copyright (C) 2003 John Lampe
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
tag_summary = "The Trend Micro Emanager software resides on this server.
Some versions of this software have vulnerable dlls.  If vulnerable, 
remote exploit is possible.  For more info, visit:
http://www.securityfocus.com/bid/3327";

tag_solution = "Remove this CGI or upgrade to the latest version of this software";

if(description)
{
 script_id(11747);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(3327);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_cve_id("CVE-2001-0958");
 
 
 name = "Trend Micro Emanager software check";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 
 summary = "Check for certain Trend Micro dlls";
 
 script_summary(summary);
 
 script_category(ACT_ATTACK); 
 
 
 script_copyright("This script is Copyright (C) 2003 John Lampe");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
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
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

flag = flag2 = 0;
directory = "";

file[0] = "register.dll";
#file[1] = "ContentFilter.dll";
#file[2] = "SFNofitication.dll";
#file[3] = "TOP10.dll";
#file[4] = "SpamExcp.dll";
#file[5] = "spamrule.dll";

for (i=0; file[i]; i = i + 1) {
foreach dir (cgi_dirs()) {
   if ( "eManager" >< dir )  flag2 = 1;
   if(is_cgi_installed_ka(item:string(dir, "/", file[i]), port:port)) {
  	flag = 1;
  	directory = dir;
  	break;
   } 
}
}

if ( (! flag2) && (! flag) )  {
	dirs[0] = "/eManager/Email%20Management/";
	dirs[1] = "/eManager/Content%20Management/";
        for (i=0; dirs[i]; i = i + 1) {
		for (q=0; file[q] ; q = q + 1) {
			if(is_cgi_installed_ka(item:string(dirs[i], file[q]) , port:port)) {
				security_hole(port);
				exit(0);
			}
   		}
	}	
 }

if (flag) security_hole (port);
