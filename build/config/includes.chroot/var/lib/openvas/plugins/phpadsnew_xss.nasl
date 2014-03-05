# OpenVAS Vulnerability Test
# $Id: phpadsnew_xss.nasl 17 2013-10-27 14:01:43Z jan $
# Description: phpAdsNew Multiple Vulnerabilities
#
# Authors:
# Noam Rathaus
# Changes by Tenable:
#  - Added a BID
#  - Added script_version()
#
# Copyright:
# Copyright (C) 2005 Noam Rathaus
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
tag_summary = "phpAdsNew is an open-source ad server, with an integrated banner
management interface and tracking system for gathering statistics.
With phpAdsNew you can easily rotate paid banners and your own
in-house advertisements. You can even integrate banners from
third party advertising companies.

The product has been found to contain two vulnerabilities:
 * Path disclosure vulnerability
 * Cross Site Scripting

An attacker may use the cross site scripting bug to preform phishing
attacks.";

# phpAdsNew 2.0.4-pr1 Multiple vulnerabilities cXIb8O3.9
# From: Maksymilian Arciemowicz <max@jestsuper.pl>
# Date: 2005-03-15 03:56

if(description)
{
 script_id(17335);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2005-0791");
 script_bugtraq_id(12803);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");

 name = "phpAdsNew Multiple Vulnerabilities";

 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 
 summary = "Checks for the presence of a XSS in phpAdsNew";
 
 script_summary(summary);
 
 script_category(ACT_ATTACK);
 
 script_copyright("This script is Copyright (C) 2005 Noam Rathaus");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "cross_site_scripting.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

debug = 0;

function check(loc)
{
 req = http_get(item: string(loc, "/adframe.php?refresh=example.com'<script>alert(document.cookie)</script>"), port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if("content='example.com\'><script>alert(document.cookie)</script>'>" >< r)
 {
  security_warning(port);
  exit(0);
 }
}

foreach dir ( cgi_dirs() ) check(loc:dir);
