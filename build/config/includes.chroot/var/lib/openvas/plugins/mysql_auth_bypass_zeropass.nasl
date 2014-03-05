# OpenVAS Vulnerability Test
# $Id: mysql_auth_bypass_zeropass.nasl 17 2013-10-27 14:01:43Z jan $
# Description: MySQL Authentication bypass through a zero-length password
#
# Authors:
# Eli Kara <elik@beyondsecurity.com>
#
# Copyright:
# Copyright (C) 2004 Beyond Security
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
tag_summary = "It is possible to bypass password authentication for a database
 user using a crafted authentication packet with a zero-length password
 
Note: In order to use this script, the MySQL daemon has to allow connection from the
scanning IP address";

if(description)
{
 script_id(12639);  
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(10654, 10655);
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 name = "MySQL Authentication bypass through a zero-length password";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary;
 script_description(desc);
 
 summary = "Log in to MySQL with a zero-length password";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2004 Beyond Security");
 
 family = "Remote file access";
 script_family(family);
 
 script_dependencies("find_service2.nasl");
 script_require_ports("Services/mysql", 3306);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

# tested by mysql_unpassworded.nasl
exit (0);
