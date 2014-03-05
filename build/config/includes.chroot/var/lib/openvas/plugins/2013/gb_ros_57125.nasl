###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ros_57125.nasl 11 2013-10-27 10:12:02Z jan $
#
# Rugged Operating System Web UI Multiple Security Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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
tag_summary = "Rugged Operating System is prone to multiple security vulnerabilities
including:

1. A session-hijacking vulnerability
2. An unauthorized-access vulnerability

Successfully exploiting these issues may allow an attacker to gain
unauthorized access to the affected application, bypass certain
security restrictions and perform unauthorized actions.

Rugged Operating System versions prior to 3.12.1 are vulnerable.";


tag_solution = "Updates are available. Please see the references for more information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103634";
CPE = "cpe:/o:ruggedcom:ros";

if (description)
{
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
   script_tag(name : "solution" , value : tag_solution);
     script_tag(name : "summary" , value : tag_summary);
 }
 script_oid(SCRIPT_OID);
 script_bugtraq_id(57125);
 script_tag(name:"cvss_base", value:"9.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
 script_version ("$Revision: 11 $");

 script_name("Rugged Operating System Web UI Multiple Security Vulnerabilities");

desc = "
   Summary:
   " + tag_summary + "
 Solution:
 " + tag_solution;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/57125");
 script_xref(name : "URL" , value : "http://www.ruggedcom.com/");

 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-01-04 12:49:46 +0100 (Fri, 04 Jan 2013)");
 script_description(desc);
 script_summary("Check the version of ros");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("gb_ros_detect.nasl");
 script_require_ports("Services/www", 80, "Services/telnet", 23);
 script_require_keys("rugged_os/installed");
 exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID))exit(0);

if(version_is_less(version:vers, test_version:"3.12.1")) {
  security_hole(port:0);
  exit(0);
}  

exit(99);
