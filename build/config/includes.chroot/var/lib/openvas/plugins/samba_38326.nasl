###############################################################################
# OpenVAS Vulnerability Test
# $Id: samba_38326.nasl 14 2013-10-27 12:33:37Z jan $
#
# Samba 'client/mount.cifs.c' Remote Denial of Service Vulnerability
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
tag_summary = "Samba is prone to a remote denial-of-service vulnerability.

A remote attacker can exploit this issue to crash the affected
application, denying service to legitimate users.

Samba 3.4.5 and earlier are vulnerable.";


if (description)
{
 script_id(100499);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-02-22 14:49:01 +0100 (Mon, 22 Feb 2010)");
 script_bugtraq_id(38326);
 script_cve_id("CVE-2010-0547");
 script_tag(name:"cvss_base", value:"2.1");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");

 script_name("Samba 'client/mount.cifs.c' Remote Denial of Service Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38326");
 script_xref(name : "URL" , value : "http://git.samba.org/?p=samba.git;a=commit;h=a065c177dfc8f968775593ba00dffafeebb2e054");
 script_xref(name : "URL" , value : "http://us1.samba.org/samba/");

 script_description(desc);
 script_summary("Determine if Samba version is < 3.4.5");
 script_category(ACT_GATHER_INFO);
 script_family("Denial of Service");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("smb_nativelanman.nasl");
 script_require_ports(139, 445);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("version_func.inc");

port = get_kb_item("SMB/transport");
if(!port)port = 139;

if(!get_port_state(port))exit(0);

if(!lanman = get_kb_item("SMB/NativeLanManager"))exit(0);
if("Samba" >!< lanman)exit(0);

if(!version = eregmatch(pattern:"Samba ([0-9.]+)", string: lanman))exit(0);
if(isnull(version[1]))exit(0);

if(version_is_less(version:version[1], test_version:"3.4.5")) {
    security_warning(port:port);
    exit(0);
}

exit(0);
