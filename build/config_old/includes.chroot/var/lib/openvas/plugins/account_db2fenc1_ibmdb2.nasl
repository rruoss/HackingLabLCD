# OpenVAS Vulnerability Test
# $Id: account_db2fenc1_ibmdb2.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Default password (ibmdb2) for db2fenc1
#
# Authors:
# Chris Foster
#
# Copyright:
# Copyright (C) 2003 Chris Foster
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
tag_solution = "Set a strong password for this account or disable it.
This may disable dependant applications so beware";
tag_summary = "The account 'db2fenc1' has the password 'ibmdb2'
An attacker may use it to gain further privileges on this system";

account = "db2fenc1";
password = "ibmdb2";

if(description)
{
 script_id(11861);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_cve_id("CVE-2001-0051");
 script_name("Default password (ibmdb2) for db2fenc1");

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
		 
 script_summary("Logs into the remote host");

 script_copyright("This script is Copyright (C) 2003 Chris Foster");

 script_category(ACT_GATHER_INFO);

 script_family("Default Accounts");
 
 script_dependencies("find_service.nasl", "ssh_detect.nasl");
 script_require_ports("Services/telnet", 23, "Services/ssh", 22);
 script_require_keys("Settings/ThoroughTests");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "solution" , value : tag_solution);
 }
 exit(0);
}

#
# The script code starts here : 
#
include("default_account.inc");
include("global_settings.inc");

if ( ! thorough_tests ) exit(0);

port = check_account(login:account, password:password);
if(port)security_hole(port);
