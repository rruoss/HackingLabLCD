###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_trac_39040.nasl 14 2013-10-27 12:33:37Z jan $
#
# Trac Ticket Validation Security Bypass Vulnerability
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
tag_summary = "Trac is prone to a security-bypass vulnerability.

Attackers can exploit this issue to bypass certain security
restrictions and perform unauthorized actions.

Versions prior to Trac 0.11.7 are vulnerable.";

tag_solution = "The vendor has released an update. Please see the references
for details.";

if (description)
{
 script_id(100563);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-03-31 12:56:41 +0200 (Wed, 31 Mar 2010)");
 script_bugtraq_id(39040);

 script_name("Trac Ticket Validation Security Bypass Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/39040");
 script_xref(name : "URL" , value : "http://trac.edgewall.org/wiki/ChangeLog#a0.11.7");
 script_xref(name : "URL" , value : "http://trac.edgewall.org/");

 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if installed version of Trac is < 0.11.7");
 script_category(ACT_GATHER_INFO);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl","http_version.nasl");
 script_require_ports("Services/www", 8000);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}
     
include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:8000);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner)exit(0);
if("Server: tracd/" >!< banner)exit(0);

version = eregmatch(pattern: "tracd/([0-9.]+)", string: banner);
if(isnull(version[1]))exit(0);

vers = version[1];

if(!isnull(vers)) {

  if(version_is_less(version: vers, test_version: "0.11.7")) {
      security_warning(port:port);
      exit(0);
  }

}

exit(0);

