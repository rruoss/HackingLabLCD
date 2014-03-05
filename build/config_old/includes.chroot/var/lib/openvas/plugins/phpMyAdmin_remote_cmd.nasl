# OpenVAS Vulnerability Test
# $Id: phpMyAdmin_remote_cmd.nasl 17 2013-10-27 14:01:43Z jan $
# Description: phpMyAdmin remote command execution
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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
tag_summary = "The remote web server contains a PHP application that may allow
arbitrary command execution. 

Description :

According to its banner, the remote version of phpMyAdmin is vulnerable
to an unspecified vulnerability in the MIME-based transformation system
with 'external' transformations that may allow arbitrary command
execution.  Successful exploitation requires that PHP's 'safe_mode' be
enabled.";

tag_solution = "Upgrade to phpMyAdmin version 2.6.0-pl2 or later.";

#  Ref: phpMyAdmin team

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.15478";
CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2004-2630");
 script_bugtraq_id(11391);
 script_xref(name:"OSVDB", value:"10715");
 
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 name = "phpMyAdmin remote command execution";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Checks the version of phpMyAdmin";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("secpod_phpmyadmin_detect_900129.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 script_require_keys("phpMyAdmin/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://secunia.com/advisories/12813/");
 exit(0);
}

# Check starts here
include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

# Test an install.
if(!ver = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

if ( ereg(pattern:"(2\.[0-5]\..*|2\.6\.0$|2\.6\.0-pl1)", string:ver) ) security_hole(port);

