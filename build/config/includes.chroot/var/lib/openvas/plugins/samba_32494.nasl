###############################################################################
# OpenVAS Vulnerability Test
# $Id: samba_32494.nasl 15 2013-10-27 12:49:54Z jan $
#
# Samba Arbitrary Memory Contents Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
tag_summary = "Samba is prone to an information-disclosure vulnerability.

Successful exploits will allow attackers to obtain arbitrary
memory contents.

This issue affects Samba 3.0.29 through 3.2.4.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(100337);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-11-04 20:13:20 +0100 (Wed, 04 Nov 2009)");
 script_bugtraq_id(32494);
 script_cve_id("CVE-2008-4314");
 script_tag(name:"cvss_base", value:"8.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:P");
 script_tag(name:"risk_factor", value:"Critical");

 script_name("Samba Arbitrary Memory Contents Information Disclosure Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/32494");
 script_xref(name : "URL" , value : "http://www.samba.org");
 script_xref(name : "URL" , value : "http://support.avaya.com/elmodocs2/security/ASA-2009-014.htm");
 script_xref(name : "URL" , value : "http://sourceforge.net/project/shownotes.php?group_id=151951&amp;release_id=503763");
 script_xref(name : "URL" , value : "http://support.nortel.com/go/main.jsp?cscat=BLTNDETAIL&amp;id=838290");
 script_xref(name : "URL" , value : "http://us1.samba.org/samba/security/CVE-2008-4314.html");
 script_xref(name : "URL" , value : "http://sunsolve.sun.com/search/document.do?assetkey=1-66-249087-1");

 script_description(desc);
 script_summary("Determine if Samba is prone to an information-disclosure vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
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
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_kb_item("SMB/transport");
if(!port)port = 139;

if(!get_port_state(port))exit(0);

if(!lanman = get_kb_item("SMB/NativeLanManager"))exit(0);
if("Samba" >!< lanman)exit(0);

if(!version = eregmatch(pattern:"Samba ([0-9.]+)", string: lanman))exit(0);
if(isnull(version[1]))exit(0);

if(version_in_range(version:version[1], test_version:"3.0.29", test_version2: "3.2.4")) {
  security_hole(port:port);
  exit(0);
}  

exit(0);

