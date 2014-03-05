###############################################################################
# OpenVAS Vulnerability Test
# $Id: samba_38111.nasl 14 2013-10-27 12:33:37Z jan $
#
# Samba Symlink Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer
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
tag_solution = "The vendor commented on the issue stating that it stems from an
insecure default configuration. The Samba team advises administrators
to set 'wide links = no' in the '[global]' section of 'smb.conf' and
then restart the service to correct misconfigured services.

Please see the references for more information.";

tag_summary = "Samba is prone to a directory-traversal vulnerability because the
application fails to sufficiently sanitize user-supplied input.

Exploits would allow an attacker to access files outside of the Samba
user's root directory to obtain sensitive information and perform
other attacks.

To exploit this issue, attackers require authenticated access to a
writable share. Note that this issue may be exploited through a
writable share accessible by guest accounts.

NOTE: The vendor stated that this issue stems from an insecure default
      configuration. The Samba team advises administrators to set
      'wide links = no' in the '[global]' section of 'smb.conf'.";


if (description)
{
 script_id(100488);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-02-08 23:29:56 +0100 (Mon, 08 Feb 2010)");
 script_bugtraq_id(38111);
 script_tag(name:"cvss_base", value:"2.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");

 script_name("Samba Symlink Directory Traversal Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38111");
 script_xref(name : "URL" , value : "http://www.samba.org/samba/news/symlink_attack.html");
 script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/fulldisclosure/2010-02/0100.html");
 script_xref(name : "URL" , value : "http://www.samba.org");
 script_xref(name : "URL" , value : "http://lists.grok.org.uk/pipermail/full-disclosure/2010-February/072927.html");

 script_description(desc);
 script_summary("Determine if Samba version is <= 3.4.5");
 script_category(ACT_GATHER_INFO);
 script_family("Remote file access");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("smb_nativelanman.nasl");
 script_require_ports(139, 445);
 script_require_keys("SMB/NativeLanManager");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "solution" , value : tag_solution);
 }
 exit(0);
}

include("version_func.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_kb_item("SMB/transport");
if(!port)port = 139;

if(!get_port_state(port))exit(0);

if(!lanman = get_kb_item("SMB/NativeLanManager"))exit(0);
if("Samba" >!< lanman)exit(0);

if(!version = eregmatch(pattern:"Samba ([0-9.]+)", string: lanman))exit(0);
if(isnull(version[1]))exit(0);

if(version_is_less_equal(version:version[1], test_version:"3.4.5")) {
  security_warning(port:port);
  exit(0);
}

exit(0);
