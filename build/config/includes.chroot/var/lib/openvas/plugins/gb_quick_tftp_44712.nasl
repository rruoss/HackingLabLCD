###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_quick_tftp_44712.nasl 14 2013-10-27 12:33:37Z jan $
#
# Quick Tftp Server Pro Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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
tag_summary = "Quick Tftp Server Pro is prone to a directory-traversal vulnerability
because it fails to sufficiently sanitize user-supplied input.

Exploiting this issue can allow an attacker to retrieve arbitrary
files outside of the FTP server root directory. This may aid in
further attacks.

Quick Tftp Server Pro 2.1 is vulnerable; other versions may also
be affected.";


if (description)
{
 script_id(100899);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-11-09 13:58:26 +0100 (Tue, 09 Nov 2010)");
 script_bugtraq_id(44712);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Quick Tftp Server Pro Directory Traversal Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/44712");
 script_xref(name : "URL" , value : "http://www.tallsoft.com/tftpserver.htm");

 script_description(desc);
 script_summary("Determine if Quick Tftp Server Pro is prone to a directory-traversal vulnerability");
 script_category(ACT_ATTACK);
 script_family("Remote file access");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("tftpd_detect.nasl", "tftpd_backdoor.nasl");
 script_require_keys("Services/udp/tftp");
 script_exclude_keys('tftp/backdoor');
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}


include("tftp.inc");

port = get_kb_item("Services/udp/tftp");
if (!port) port = 69;
if (get_kb_item('tftp/'+port+'/backdoor')) exit(0);

get = tftp_get(port:port, path:"../../../../../../../../../../../../boot.ini");
if (isnull(get)) exit(0);

if("[boot loader]" >< get) {
  security_warning(port:port);
  exit(0);
}  

exit(0);
