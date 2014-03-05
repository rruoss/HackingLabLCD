###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sun_java_system_application_server_41638.nasl 14 2013-10-27 12:33:37Z jan $
#
# Sun Java System Application Server CVE-2010-2397 Local Vulnerability
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
tag_summary = "Sun Java System Application Server is prone to a local vulnerability.

The 'GUI' sub component is affected.

This vulnerability affects the following supported versions: Sun Java
System Application Server 8.0, 8.1, 8.2.";

tag_solution = "Vendor updates are available. Please contact the vendor for more
information.";

if (description)
{
 script_id(100715);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-07-14 13:50:55 +0200 (Wed, 14 Jul 2010)");
 script_bugtraq_id(41638);
 script_tag(name:"cvss_base", value:"2.4");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:P/I:P/A:N");
 script_cve_id("CVE-2010-2397");

 script_name("Sun Java System Application Server Local Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/41638");
 script_xref(name : "URL" , value : "http://www.oracle.com/technology/deploy/security/critical-patch-updates/cpujul2010.html");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if installed Sun Java System Application Server version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("secpod_sun_java_app_serv_detect.nasl");
 script_require_keys("Sun/Java/AppServer/Ver");
 script_require_ports("Services/www", 80, 8080);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!port){
    exit(0);
}

appservVer = get_kb_item("Sun/Java/AppServer/Ver");
if(isnull(appservVer))exit(0);

if(version_in_range(version:appservVer, test_version:"8",test_version2:"8.2")) {
  security_warning(port:port);
  exit(0);
}  

exit(0);
