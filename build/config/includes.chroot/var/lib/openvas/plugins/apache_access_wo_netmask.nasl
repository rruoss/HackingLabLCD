# OpenVAS Vulnerability Test
# $Id: apache_access_wo_netmask.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Apache mod_access rule bypass
#
# Authors:
# George A. Theall, <theall@tifaware.com>.
#
# Copyright:
# Copyright (C) 2004 George A. Theall
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
tag_summary = "The target is running an Apache web server that may not properly handle
access controls.  In effect, on big-endian 64-bit platforms, Apache
fails to match allow or deny rules containing an IP address but not a
netmask. 

*****  OpenVAS has determined the vulnerability exists only by looking at
*****  the Server header returned by the web server running on the target.
*****  If the target is not a big-endian 64-bit platform, consider this a 
*****  false positive. 

Additional information on the vulnerability can be found at :

  - http://www.apacheweek.com/features/security-13
  - http://marc.theaimsgroup.com/?l=apache-cvs&m=107869603013722
  - http://nagoya.apache.org/bugzilla/show_bug.cgi?id=23850";

tag_solution = "Upgrade to Apache version 1.3.31 or newer.";

if (description) {
  script_id(14177);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(9829);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");

  script_cve_id("CVE-2003-0993");
  script_xref(name:"GLSA", value:"GLSA 200405-22");
  script_xref(name:"MDKSA", value:"MDKSA-2004:046");
  script_xref(name:"OpenPKG-SA", value:"OpenPKG-SA-2004.021-apache");
  script_xref(name:"SSA", value:"SSA:2004-133-01");
  script_xref(name:"TSLSA", value:"TSLSA-2004-0027");

  name = "Apache mod_access rule bypass";
  script_name(name);
 
  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;
  script_description(desc);

  summary = "Checks for Apache mod_access Rule Bypass Vulnerability";
  script_summary(summary);

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 George A. Theall");

  family = "General";
  script_family(family);

  script_dependencies("find_service.nasl", "global_settings.nasl", "http_version.nasl");
  script_dependencies("gather-package-list.nasl");
  script_require_keys("www/apache");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("backport.inc");
include("global_settings.inc");
include("http_func.inc");

if ( report_paranoia < 2 ) exit(0);

uname = get_kb_item("ssh/login/uname");
if ( uname )
{
 if ( egrep(pattern:"i.86", string:uname) ) exit(0);
}
host = get_host_name();
port = get_http_port(default:80);
if (debug_level) display("debug: checking for mod_access Rule Bypass vulnerability on ", host, ":", port, ".\n");

if (!get_port_state(port)) exit(0);

# Check the web server's banner for the version.
banner = get_http_banner(port:port);
if (!banner) exit(0);
banner = get_backport_banner(banner:banner);

sig = strstr(banner, "Server:");
if (!sig) exit(0);
if (debug_level) display("debug: server sig = >>", sig, "<<.\n");

if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/1\.([0-2]\.[0-9]|3\.([0-9][^0-9]|[0-2][0-9]))", string:sig)) {
  security_hole(port);
}
