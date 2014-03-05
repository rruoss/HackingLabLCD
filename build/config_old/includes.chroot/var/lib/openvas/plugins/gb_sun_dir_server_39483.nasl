###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sun_dir_server_39483.nasl 14 2013-10-27 12:33:37Z jan $
#
# Oracle Java System Directory Server CVE-2010-0897 Multiple Remote Vulnerabilities
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
tag_summary = "Oracle Java System Directory Server is prone to multiple remote
vulnerabilities.

These vulnerabilities can be exploited over the 'LDAP' and 'HTTP'
protocols. Remote attackers can exploit these issues without
authenticating.

Successful exploits will allow attackers to exploit arbitrary code in
the context of the vulnerable application or cause denial-of-service
conditions.

These vulnerabilities affect the following supported versions:
5.2, 6.0, 6.1, 6.2, 6.3, 6.3.1";

tag_solution = "Vendor updates are available. Please contact the vendor for more
information.";

if (description)
{
 script_id(100577);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-04-15 19:15:10 +0200 (Thu, 15 Apr 2010)");
 script_bugtraq_id(39453);
 script_cve_id("CVE-2010-0897");

 script_name("Oracle Java System Directory Server Multiple Remote Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/39453");
 script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-10-073/");
 script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-10-074/");
 script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-10-075/");
 script_xref(name : "URL" , value : "http://www.oracle.com/technology/deploy/security/critical-patch-updates/cpuapr2010.html");

 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if installed Sun Java System Directory Server version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("sun_dir_server_detect.nasl");
 script_require_ports("Services/ldap", 389);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("version_func.inc");

port = get_kb_item("Services/ldap");
if(!port)exit(0);
if(!get_port_state(port))exit(0);

if(!version = get_kb_item(string("ldap/",port,"/SunJavaDirServer")))exit(0);

if(!isnull(version)) {
  if(version_in_range(version: version, test_version: "6", test_version2: "6.3.1") ||
     version_is_equal(version: version, test_version: "5.2")) {
       security_hole(port: port);
       exit(0);
  }     
}  

exit(0);
