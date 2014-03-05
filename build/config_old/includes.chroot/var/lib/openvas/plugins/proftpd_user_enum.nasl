# OpenVAS Vulnerability Test
# $Id: proftpd_user_enum.nasl 17 2013-10-27 14:01:43Z jan $
# Description: proftpd < 1.2.11 remote user enumeration
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
tag_summary = "The remote ProFTPd server is as old or older than 1.2.10

It is possible to determine which user names are valid on the remote host 
based on timing analysis attack of the login procedure.

An attacker may use this flaw to set up a list of valid usernames for a
more efficient brute-force attack against the remote host.";

tag_solution = "Upgrade to a newer version";

#  Ref: LSS Security

if(description)
{
 script_id(15484);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_bugtraq_id(11430);
 script_cve_id ("CVE-2004-1602");
 
 name = "proftpd < 1.2.11 remote user enumeration";
 
 script_name(name);
             
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

                 
                     
 script_description(desc);
                    
 
 script_summary("Checks the version of the remote proftpd");
 script_category(ACT_GATHER_INFO);
 script_family("FTP");

 script_copyright("This script is Copyright (C) 2004 David Maciejak");
                  
 script_dependencies("find_service.nasl", "secpod_ftp_anonymous.nasl");
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
if(egrep(pattern:"^220 ProFTPD 1\.2\.([0-9][^0-9]|10[^0-9])", string:banner))
{
  security_warning(port);
}
