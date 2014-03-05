###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_samba_40097.nasl 14 2013-10-27 12:33:37Z jan $
#
# Samba Multiple Remote Denial of Service Vulnerabilities
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
tag_summary = "Samba is prone to multiple remote denial-of-service vulnerabilities.

An attacker can exploit these issues to crash the application, denying
service to legitimate users.

Versions prior to Samba 3.4.8 and 3.5.2 are vulnerable.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(100644);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-05-19 12:58:40 +0200 (Wed, 19 May 2010)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2010-1635");
 script_bugtraq_id(40097);

 script_name("Samba Multiple Remote Denial of Service Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/40097");
 script_xref(name : "URL" , value : "https://bugzilla.samba.org/show_bug.cgi?id=7254");
 script_xref(name : "URL" , value : "http://samba.org/samba/history/samba-3.4.8.html");
 script_xref(name : "URL" , value : "http://samba.org/samba/history/samba-3.5.2.html");
 script_xref(name : "URL" , value : "http://www.samba.org");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if is prone to multiple remote denial-of-service vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family("Denial of Service");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("smb_nativelanman.nasl");
 script_require_ports(139, 445);
 script_require_keys("SMB/NativeLanManager");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
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

if(!version = eregmatch(pattern:"Samba ([0-9.]+)", string:lanman))exit(0);
if(isnull(version[1]))exit(0);

if(version_in_range(version:version[1], test_version:"3.5", test_version2: "3.5.1")  ||
   version_in_range(version:version[1], test_version:"3.4", test_version2: "3.4.7")) {
     security_warning(port:port);
     exit(0);
}

exit(0);
