# OpenVAS Vulnerability Test
# $Id: vpasswd_cgi.nasl 17 2013-10-27 14:01:43Z jan $
# Description: vpasswd.cgi
#
# Authors:
# Michel Arboi
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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
tag_summary = "The 'vpasswd.cgi' CGI is installed. Some versions
do not properly check for special characters and allow
a cracker to execute any command on your system.

*** Warning : OpenVAS solely relied on the presence of this CGI, it did not
*** determine if you specific version is vulnerable to that problem";

tag_solution = "remove it from /cgi-bin.";

# References
# Date: Thu, 24 Oct 2002 10:41:48 -0700 (PDT)
# From:"Jeremy C. Reed" <reed@reedmedia.net> 
# To:bugtraq@securityfocus.com
# Subject: Re: vpopmail CGIapps vpasswd vulnerabilities
# In-Reply-To: <200210241126.33510.n.bugtraq@icana.org.ar>
# Message-ID: <Pine.LNX.4.43.0210241020040.25224-100000@pilchuck.reedmedia.net>

if(description)
{
 script_id(11165);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(6038);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");

 name = "vpasswd.cgi";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;



 script_description(desc);
 
 summary = "Checks for the presence of vpasswd.cgi";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

# The script code starts here
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);


port = get_http_port(default:80);

res = is_cgi_installed_ka(item:"vpasswd.cgi", port:port);
if(res)security_hole(port);