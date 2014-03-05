###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_axon_39483.nasl 14 2013-10-27 12:33:37Z jan $
#
# NCH Software Axon 2.13 Multiple Remote Vulnerabilities
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
tag_summary = "NCH Software Axon virtual PBX is prone to multiple remote
vulnerabilities, including:

- A cross-site scripting vulnerability.
- A cross-site request forgery vulnerability.
- An arbitrary file deletion vulnerability.
- A directory traversal vulnerability.

An attacker may leverage these issues to cause a denial-of-service
condition, run arbitrary script code in the browser of an unsuspecting
user in the context of the affected application, steal cookie-based
authentication credentials, perform certain administrative actions,
gain unauthorized access to the affected application, delete certain
data, and overwrite arbitrary files. Other attacks are also possible.

Axon 2.13 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(100576);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-04-15 19:15:10 +0200 (Thu, 15 Apr 2010)");
 script_bugtraq_id(39483);
 script_tag(name:"cvss_base", value:"2.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
 script_name("NCH Software Axon 2.13 Multiple Remote Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/39483");
 script_xref(name : "URL" , value : "http://www.nch.com.au/pbx/index.html");
 script_xref(name : "URL" , value : "http://nchsoftware.com/");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if Axon virtual PBX version is 2.13");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("secpod_axon_virtual_pbx_detect.nasl");
 script_require_keys("Axon-Virtual-PBX/Ver");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

axonPort = get_http_port(default:81);
if(!get_port_state(axonPort)){
    exit(0);
}

req = http_get_cache(item:"/", port:axonPort);
if(req == NULL || "Axon - Login" >!< req)exit(0);
if(!axonVer = get_kb_item("Axon-Virtual-PBX/Ver"))exit(0);

if(!isnull(axonVer)) {

  if(version_is_equal(version: axonVer, test_version:"2.13")) {
    security_warning(port: axonPort);
    exit(0);
  }  

}  

exit(0);
