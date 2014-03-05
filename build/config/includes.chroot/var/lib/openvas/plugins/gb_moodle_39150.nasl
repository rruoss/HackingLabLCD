###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_moodle_39150.nasl 14 2013-10-27 12:33:37Z jan $
#
# Moodle Prior to 1.9.8/1.8.12 Multiple Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
tag_summary = "Moodle is prone to multiple vulnerabilities, including:

- multiple cross-site scripting issues
- a security-bypass issue
- an information-disclosure issue
- multiple SQL-injection issues
- an HTML-injection issue
- a session-fixation issue

Attackers can exploit these issues to bypass certain security
restrictions, obtain sensitive information, perform unauthorized
actions, compromise the application, access or modify data, or exploit
latent vulnerabilities in the underlying database. Other attacks may
also be possible.

These issues affect versions prior to Moodle 1.9.8 and 1.8.12.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(100569);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-04-12 18:40:45 +0200 (Mon, 12 Apr 2010)");
 script_bugtraq_id(39150);
 script_tag(name:"cvss_base", value:"2.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");

 script_name("Moodle Prior to 1.9.8/1.8.12 Multiple Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/39150");
 script_xref(name : "URL" , value : "http://docs.moodle.org/en/Moodle_1.9.8_release_notes");
 script_xref(name : "URL" , value : "http://www.moodle.org");
 script_xref(name : "URL" , value : "http://moodle.org/security/");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if installed Moodle version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_moodle_cms_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("Moodle/Version");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if (!can_host_php(port:port)) exit(0);

if(vers = get_version_from_kb(port:port,app:"moodle")) {

  if(vers =~ "1\.8") {
    
    if(version_is_less(version: vers, test_version: "1.8.9")) {
      security_warning(port:port);
      exit(0);
    }
  
  } else if(vers =~ "1\.9") {
  
    if(version_is_less(version: vers, test_version: "1.9.8")) {
      security_warning(port:port);
      exit(0);
    }
  }
}

exit(0);
