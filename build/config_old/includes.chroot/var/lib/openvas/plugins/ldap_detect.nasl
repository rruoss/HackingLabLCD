###############################################################################
# OpenVAS Vulnerability Test
# $Id: ldap_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# Detection of LDAP
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
tag_summary = "A LDAP Server is running at this host.

  The Lightweight Directory Access Protocol, or LDAP is an application
  protocol for querying and modifying directory services running over
  TCP/IP.";

if (description)
{
 script_id(100082);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2009-03-27 12:39:47 +0100 (Fri, 27 Mar 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");

 desc = "
 Summary:
 " + tag_summary;

 script_name("LDAP Detection");  

 script_description(desc);
 script_summary("Check for LDAP");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/ldap", 389);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("misc_func.inc");
include("ldap.inc");

port = get_kb_item("Services/ldap");
if(!port)port = 389;
if(!get_port_state(port))exit(0);

if(ldap_alive(port:port)) {
  register_service(port:port, ipproto:"tcp", proto:"ldap");
  security_note(port:port);
  exit(0);
}

exit(0);
