# OpenVAS Vulnerability Test
# $Id: viralator.nasl 16 2013-10-27 13:09:52Z jan $
# Description: viralator
#
# Authors:
# Renaud Deraison <deraison@cvs.nessus.org>
#
# Copyright:
# Copyright (C) 2002 Renaud Deraison
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
tag_summary = "The CGI 'viralator.cgi' is installed.
Some versions of this CGI are don't check properly the user
input and allow anyone to execute arbitrary commands with
the privileges of the web server

** No flaw was tested. Your script might be a safe version.

Solutions : Upgrade this script to version 0.9pre2 or newer";

# References:
# http://marc.info/?l=bugtraq&m=100463639800515&w=2

if(description)
{
 script_id(80093);;
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_bugtraq_id(3495);
 script_cve_id("CVE-2001-0849");
 name = "viralator";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;


 script_description(desc);
 
 summary = "Checks for the presence of /cgi-bin/viralator.cgi";

 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("This script is Copyright (C) 2002 Renaud Deraison");

 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);
res = is_cgi_installed_ka(item:"viralator.cgi", port:port);
if( res )security_hole(port);



