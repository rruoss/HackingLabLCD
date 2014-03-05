# OpenVAS Vulnerability Test
# $Id: php_nuke_admin_cp.nasl 17 2013-10-27 14:01:43Z jan $
# Description: PHP-Nuke copying files security vulnerability (admin.php)
#
# Authors:
# SecurITeam
# Updated: 2009/04/24
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (C) 2001 SecurITeam
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_summary = "The remote host seems to be vulnerable to a security problem in
  PHP-Nuke (admin.php).
  The vulnerability is caused by inadequate processing of queries
  by PHP-Nuke's admin.php which enables attackers to copy any file
  from the operating system to anywhere else on the operating system.";

tag_solution = "Change the following lines in admin.php:
  if($upload)
  To:
  if(($upload) && ($admintest))
  Or upgrade to the latest version (Version 5.3 and above).

  Additional information:
  http://www.securiteam.com/unixfocus/TOBA";

tag_impact = "Every file that the webserver has access to can be read by anyone.
  Furthermore, any file can be overwritten.
  Usernames (used for database access) can be compromised.
  Administrative privileges can be gained by copying sensitive files.";

if (description)
{
  script_id(10772);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(3361);
  script_cve_id("CVE-2001-1032");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("PHP-Nuke copying files security vulnerability (admin.php)");
  desc = "
  Summary:
  " + tag_summary + "
  Impact:
  " + tag_impact + "

  Solution:
  " + tag_solution;
  script_description(desc);
  script_summary("Determine if a remote host is vulnerable to the admin.php vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2001 SecurITeam");
  script_dependencies("secpod_php_nuke_detect.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port)){
  exit(0);
}

phpVer =get_kb_item("www/" + port + "/php-nuke");
phpVer = eregmatch(pattern:"(.*) under (.*)", string:phpVer);

if(phpVer[1] == NULL && phpVer[2] == NULL){
   exit(0);
}

version=phpVer[1];
dir = phpVer[2];

if(!safe_checks())
{
  data = string(dir, "admin.php?upload=1&file=config.php&file_name=openvas.txt&wdir=/images/&userfile=config.php&userfile_name=openvas.txt");
  req = http_get(item:data, port:port);
  buf = http_keepalive_send_recv(port:port, data:req);
  if(buf == NULL){
    exit(0);
  }
  if("SAFE MODE " >< buf)
  {
    security_note(port);
    exit(0);
   }
   if("Unable to create " >< buf)
   {
     security_hole(port);
     exit(0);
   }
   req = http_get(item:"/images/openvas.txt", port:port);
   buf = http_keepalive_send_recv(port:port, data:req);
   if(("PHP-NUKE: Web Portal System" >< buf) && (("?php" >< buf) || ("?PHP" >< buf)))
   {
     security_hole(port);
     exit(0);
   }
}

if(version_is_less_equal(version:version,test_version:"5.4")){
   security_warning(port);
}
