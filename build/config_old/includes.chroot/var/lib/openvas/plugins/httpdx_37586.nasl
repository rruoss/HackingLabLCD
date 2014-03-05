###############################################################################
# OpenVAS Vulnerability Test
# $Id: httpdx_37586.nasl 14 2013-10-27 12:33:37Z jan $
#
# httpdx Space Character Remote File Disclosure Vulnerability
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
tag_summary = "httpdx is prone to a remote file-disclosure vulnerability because it
fails to properly sanitize user-supplied input.

An attacker can exploit this vulnerability to view the source code
of files in the context of the server process. This may aid in
further attacks.

httpdx 1.5 is affected; other versions may be vulnerable as well.";


if (description)
{
 script_id(100421);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-01-05 18:50:28 +0100 (Tue, 05 Jan 2010)");
 script_bugtraq_id(37586);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");

 script_name("httpdx Space Character Remote File Disclosure Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37586");
 script_xref(name : "URL" , value : "http://sourceforge.net/projects/httpdx/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/508696");

 script_description(desc);
 script_summary("Determine if httpdx version is 1.5");
 script_category(ACT_GATHER_INFO);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_httpdx_server_detect.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("version_func.inc");

httpdxPort = get_http_port(default:80);
if(!httpdxPort){
  exit(0);
}

httpdxVer = get_kb_item("httpdx/" + httpdxPort + "/Ver");
if(!isnull(httpdxVer))
{
  if(version_is_equal(version:httpdxVer, test_version:"1.5")){
    security_warning(httpdxPort);
  }
}
