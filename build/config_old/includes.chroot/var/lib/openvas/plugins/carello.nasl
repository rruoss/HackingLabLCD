# OpenVAS Vulnerability Test
# $Id: carello.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Carello detection
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
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
tag_summary = "Carello.dll was found on your web server. 
Versions up to 1.3 of this web shopping cart allowed anybody
to run arbitrary commands on your server.

*** Note that no attack was performed, and the version number was
*** not checked, so this might be a false alert";

tag_solution = "Upgrade to the latest version if necessary";

# References:
#
# Date: Wed, 02 Oct 2002 17:10:21 +0100
# From: "Matt Moore" <matt@westpoint.ltd.uk>
# To: bugtraq@securityfocus.com, vulnwatch@vulnwatch.org
# Subject: wp-02-0012: Carello 1.3 Remote File Execution (Updated 1/10/2002)
#
# http://www.westpoint.ltd.uk/advisories/wp-02-0012.txt

if(description)
{
 script_id(11776);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(2729);
 script_cve_id("CVE-2001-0614");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 name = "Carello detection";

 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Checks for the presence of carello.dll";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2003 Michel Arboi");
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

#
# Please note that it is possible to test this vulnerability, but
# I suspect that Carello is not widely used, and I am lazy :-)
# 
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);

res = is_cgi_installed_ka(item:"Carello.dll", port:port);
if (res) security_hole(port);
