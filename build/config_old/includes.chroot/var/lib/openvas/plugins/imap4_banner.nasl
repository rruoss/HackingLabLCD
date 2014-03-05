# OpenVAS Vulnerability Test
# $Id: imap4_banner.nasl 17 2013-10-27 14:01:43Z jan $
# Description: IMAP Banner
#
# Authors:
# Vincent Renardias <vincent@strongholdnet.com>
#
# Copyright:
# Copyright (C) 2003 StrongHoldNet
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
tag_summary = "Displays the imap4 service banner.";

if(description)
{
 script_id(11414);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("IMAP Banner");
 
 desc = "
 Summary:
 " + tag_summary;

 script_copyright("This script is Copyright (C) 2003 StrongHoldNet");
 script_description(desc);
 script_summary("displays the imap4 banner");
 script_category(ACT_GATHER_INFO);
 script_family("General"); 
 script_dependencies("find_service.nasl");
 script_require_ports("Services/imap", 143);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}


port = get_kb_item("Services/imap");

if(!port) port = 143;
if(!get_port_state(port))exit(0);

banner = get_kb_item(string("imap/banner/", port));

if(banner)
{
 if (!ereg(pattern:"\* OK", string:banner)) exit(0);
 report = string("The remote imap server banner is :\n",banner,"\n");
 log_message(port:port, data:report);
}

