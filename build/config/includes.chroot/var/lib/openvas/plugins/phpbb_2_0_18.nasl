# OpenVAS Vulnerability Test
# $Id: phpbb_2_0_18.nasl 17 2013-10-27 14:01:43Z jan $
# Description: phpBB <= 2.0.18 Multiple Cross-Site Scripting Flaws
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2006 David Maciejak
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
tag_summary = "The remote web server contains a PHP application that is affected by
several flaws. 

Description :

According to its version number, the remote version of this software
is vulnerable to Javascript injection issues using 'url' bbcode tags
and, if HTML tags are enabled, HTML more generally.  This may allow an
attacker to inject hostile Javascript into the forum system, to steal
cookie credentials or misrepresent site content.  When the form is
submitted the malicious Javascript will be incorporated into
dynamically generated content.";

tag_solution = "Upgrade to phpBB version 2.0.19 or later.";

if (description) {
  script_id(20379);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"2.0");
  script_tag(name:"cvss_base_vector", value:"AV:R/AC:L/Au:N/C:P/A:N/I:N/B:N");
  script_tag(name:"risk_factor", value:"Low");
  script_bugtraq_id(16088);

  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;

  script_name("phpBB <= 2.0.18 Multiple Cross-Site Scripting Flaws");
  script_summary("Checks for multiple cross-site scripting flaws in phpBB <= 2.0.18");

  script_description(desc);
 
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");

  script_copyright("This script is Copyright (C) 2006 David Maciejak");

  script_dependencies("phpbb_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://lists.grok.org.uk/pipermail/full-disclosure/2005-December/040204.html");
  script_xref(name : "URL" , value : "http://www.phpbb.com/phpBB/viewtopic.php?f=14&amp;t=352966");
  exit(0);
}


include("global_settings.inc");
include("http_func.inc");


if (report_paranoia < 2) exit(0);


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

install = get_kb_item(string("www/", port, "/phpBB"));
if (isnull(install)) exit(0);


matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
	version = matches[1];
	if ( ereg(pattern:"^([01]\..*|2\.0\.([0-9]|1[0-8])[^0-9])", string:version)) {
	   security_note(port);
	   exit(0);
	}
}
