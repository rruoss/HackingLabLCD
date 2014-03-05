###############################################################################
# OpenVAS Vulnerability Test
# $Id: samba_multiple_vulnerabilities.nasl 15 2013-10-27 12:49:54Z jan $
#
# Samba multiple vulnerabilities 
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
tag_summary = "Samba is prone to multiple vulnerabilities including a vulnerability
that may allow attackers to bypass certain security restrictions, an
information-disclosure vulnerability and a remote denial-of-service
vulnerability.

Successful exploits may allow attackers to gain access to resources
that aren't supposed to be shared, allow attackers to obtain sensitive
information that may aid in further attacks and to cause the
application to consume excessive CPU resources, denying service to
legitimate users. 

Versions prior to Samba 3.4.2, 3.3.8, 3.2.15, and 3.0.37 are
vulnerable.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(100306);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-10-15 20:14:59 +0200 (Thu, 15 Oct 2009)");
 script_bugtraq_id(36363,36572,36573);
 script_cve_id("CVE-2009-2813","CVE-2009-2948","CVE-2009-2906");
 script_tag(name:"cvss_base", value:"6.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 script_name("Samba multiple vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/36363");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/36573");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/36572");
 script_xref(name : "URL" , value : "http://www.samba.org/samba/security/CVE-2009-2813.html");
 script_xref(name : "URL" , value : "http://www.samba.org/samba/security/CVE-2009-2948.html");
 script_xref(name : "URL" , value : "http://www.samba.org/samba/security/CVE-2009-2906.html");
 script_xref(name : "URL" , value : "http://www.samba.org/samba/history/security.html");
 script_xref(name : "URL" , value : "http://us1.samba.org/samba/");

 script_description(desc);
 script_summary("Determine if Samba is prone to multiple vulnerabilities");
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

if(version_in_range(version:version[1], test_version:"3.4", test_version2: "3.4.1") ||
   version_in_range(version:version[1], test_version:"3.3", test_version2: "3.3.7") ||
   version_in_range(version:version[1], test_version:"3.2", test_version2: "3.2.14") ||
   version_in_range(version:version[1], test_version:"3.0", test_version2: "3.0.36"))
   {
    security_hole(port:port);
    exit(0);
   }  

exit(0);
