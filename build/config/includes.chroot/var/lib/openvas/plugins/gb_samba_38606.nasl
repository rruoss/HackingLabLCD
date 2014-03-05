###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_samba_38606.nasl 14 2013-10-27 12:33:37Z jan $
#
# Samba 'CAP_DAC_OVERRIDE' File Permissions Security Bypass Vulnerability
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
tag_summary = "Samba is prone to a vulnerability that may allow attackers to bypass
certain security restrictions.

Successful exploits may allow attackers to gain unauthorized write and
read access to files.

This issue affects Samba versions 3.3.11, 3.4.6 and 3.5.0. Versions
3.4.5 and prior and 3.3.10 and prior are not affected.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(100522);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-03-09 22:32:06 +0100 (Tue, 09 Mar 2010)");
 script_bugtraq_id(38606);
 script_cve_id("CVE-2010-0728");
 script_tag(name:"cvss_base", value:"8.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");

 script_name("Samba 'CAP_DAC_OVERRIDE' File Permissions Security Bypass Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38606");
 script_xref(name : "URL" , value : "https://bugzilla.samba.org/show_bug.cgi?id=7222");
 script_xref(name : "URL" , value : "http://us1.samba.org/samba/");
 script_xref(name : "URL" , value : "http://us1.samba.org/samba/security/CVE-2010-0728.html");

 script_description(desc);
 script_summary("Determine if Samba version is vulnerable.");
 script_category(ACT_GATHER_INFO);
 script_family("General");
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

if(version_is_equal(version:version[1], test_version:"3.3.11") ||
   version_is_equal(version:version[1], test_version:"3.4.6")  ||
   version_is_equal(version:version[1], test_version:"3.5.0")  ||
   version_in_range(version:version[1], test_version:"3.4", test_version2: "3.4.5")  ||
   version_in_range(version:version[1], test_version:"3.3", test_version2: "3.3.10")) {
     security_hole(port:port);
     exit(0);
}

exit(0);

