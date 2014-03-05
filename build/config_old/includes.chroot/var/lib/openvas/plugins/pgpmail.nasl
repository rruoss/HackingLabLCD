# OpenVAS Vulnerability Test
# $Id: pgpmail.nasl 17 2013-10-27 14:01:43Z jan $
# Description: PGPMail.pl detection
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added CAN. Added link to the Bugtraq message archive
#
# Copyright:
# Copyright (c) 2002 Michel Arboi
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
tag_summary = "The 'PGPMail.pl' CGI is installed. 
Some versions (up to v1.31 a least) of this CGI do not
properly filter user input before using it inside commands.
This would allow a cracker to run any command on your server.

*** Note: OpenVAS just checked the presence of this CGI 
*** but did not try to exploit the flaws.";

tag_solution = "remove it from /cgi-bin or upgrade it.

Reference : http://online.securityfocus.com/archive/82/243262
Reference : http://online.securityfocus.com/archive/1/243408";


# References:
# From: joetesta@hushmail.com
# To: bugtraq@securityfocus.com, jscimone@cc.gatech.edu
# Subject: Vulnerabilities in PGPMail.pl
# Date: Thu, 29 Nov 2001 19:45:38 -0800
# 
# John Scimone <jscimone@cc.gatech.edu>.  
# <http://www.securityfocus.com/archive/82/243262>
#

if(description)
{
 script_id(11070);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(3605);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_cve_id("CVE-2001-0937");
 
 name = "PGPMail.pl detection";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 
 summary = "Checks for the presence of PGPMail.pl";

 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
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
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);
res = is_cgi_installed_ka(port:port, item:"PGPMail.pl");
if(res) security_hole(port);
