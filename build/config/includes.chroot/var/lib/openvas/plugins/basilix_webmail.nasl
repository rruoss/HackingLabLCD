# OpenVAS Vulnerability Test
# $Id: basilix_webmail.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Basilix Webmail Dummy Request Vulnerability
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
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
tag_summary = "The remote web server contains a PHP script that is prone to information
disclosure. 

Description :

The script 'basilix.php3' is installed on the remote web server.  Some
versions of this webmail software allow the users to read any file on
the system with the permission of the webmail software, and execute any
PHP.";

tag_solution = "Update Basilix or remove DUMMY from lang.inc.";

# References:
# From: "karol _" <su@poczta.arena.pl>
# To: bugtraq@securityfocus.com
# CC: arslanm@Bilkent.EDU.TR
# Date: Fri, 06 Jul 2001 21:04:55 +0200
# Subject: basilix bug

if(description)
{
 script_id(11072);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(2995);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
 script_cve_id("CVE-2001-1045");
 name = "Basilix Webmail Dummy Request Vulnerability";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution; script_description(desc);
 
 summary = "Checks for the presence of basilix.php3";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO); 

 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family = "Web application abuses";
 script_family(family);

 script_dependencies("http_version.nasl", "logins.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("imap/login", "imap/password");

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2001-07/0114.html");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


user = get_kb_item("imap/login");
pass = get_kb_item("imap/password");
if (!user || !pass) {
  if (log_verbosity > 1) display("imap/login and/or imap/password are empty; ", SCRIPT_NAME, " skipped!\n");
  exit(1);
}


url=string("/basilix.php3?request_id[DUMMY]=../../../../../../../../../etc/passwd&RequestID=DUMMY&username=", user, "&password=", pass);
if(is_cgi_installed_ka(port:port, item:url)){ security_warning(port); exit(0); }
