# OpenVAS Vulnerability Test
# $Id: flash_ftp_server_directory_traversal.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Flash FTP Server Directory Traversal Vulnerability
#
# Authors:
# Noam Rathaus <noamr@beyondsecurity.com>
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
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
tag_summary = "Flash FTP Server easy-to-set-up FTP server for all Windows platforms.
Some bugs were found that will allow a malicious user to write and 
read anywhere on the disk.";

tag_solution = "Upgrade to the latest version of this software";

# Author: dr_insane
# Subject: Flash Ftp server 1.0 Directory traversal
# Date: January 1, 2004
# http://packetstormsecurity.nl/0401-exploits/Flash.txt
# http://www.secunia.co.uk/advisories/10522/

if(description)
{
 script_id(11978);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2004-1783");
 script_bugtraq_id(9350);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 
 name = "Flash FTP Server Directory Traversal Vulnerability";
 
 script_name(name);
             
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 script_summary("Checks if the version Flash FTP Server");
 script_category(ACT_GATHER_INFO);
 script_family("FTP");

 
 script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
                  
 script_dependencies("find_service.nasl");
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

port = get_kb_item("Services/ftp");
if(!port)port = 21;

banner = get_ftp_banner(port:port);
if ( ! banner ) exit(0);

if(egrep(pattern:"^220 Flash FTP Server v(1\.|2\.[0-1]) ready", string:banner))security_hole(port);

