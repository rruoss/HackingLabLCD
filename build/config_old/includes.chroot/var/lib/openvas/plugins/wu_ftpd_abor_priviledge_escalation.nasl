# OpenVAS Vulnerability Test
# $Id: wu_ftpd_abor_priviledge_escalation.nasl 17 2013-10-27 14:01:43Z jan $
# Description: wu-ftpd ABOR priviledge escalation
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
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
tag_summary = "The remote Wu-FTPd server seems to be vulnerable to a remote priviledge 
escalation.

This version contains a flaw that may allow a malicious user to gain
access to unauthorized privileges. 

Specifically, there is a flaw in the way that the server handles
an ABOR command after a data connection has been closed.  The 
flaw is within the dologout() function and proper exploitation
will give the remote attacker the ability to execute arbitrary 
code as the 'root' user.

This flaw may lead to a loss of confidentiality and/or integrity.

*** OpenVAS solely relied on the banner of the remote server
*** to issue this warning, so it may be a false positive.";

tag_solution = "Upgrade to Wu-FTPd 2.4.2 or newer";

# Ref: David Greenman <dg at root dot com>

if(description)
{
 script_id(14301);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-1999-1326");
 script_xref(name:"OSVDB", value:"8718");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");

 
 name = "wu-ftpd ABOR priviledge escalation";
 
 script_name(name);
	     
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
		    
 
 script_summary("Checks the banner of the remote wu-ftpd server");
 script_category(ACT_GATHER_INFO);
 script_family("FTP");
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
		  
 script_dependencies("find_service.nasl", "ftpserver_detect_type_nd_version.nasl", "secpod_ftp_anonymous.nasl");
 script_require_keys("ftp/login", "ftp/wuftpd");
 script_require_ports("Services/ftp", 21);
  
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here : 
#
include("ftp_func.inc");

#login = get_kb_item("ftp/login");
#pass  = get_kb_item("ftp/password");

port = get_kb_item("Services/ftp");
if(!port)
	port = 21;
if (! get_port_state(port)) 
	exit(0);

banner = get_ftp_banner(port: port);
if( banner == NULL ) 
	exit(0);

if(egrep(pattern:".*wu-(2\.([0-3]\.|4\.[01])).*", string:banner))
	security_warning(port);
