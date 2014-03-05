###############################################################################
# OpenVAS Vulnerability Test
# $Id: php_34475.nasl 15 2013-10-27 12:49:54Z jan $
#
# PHP cURL 'safe_mode' and 'open_basedir' Restriction-Bypass
# Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# Updated to PHP Get KB Item Method
#   -By Sharath S <sharaths@secpod.com> on 2009-04-17
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "PHP is prone to a safe_mode and open_basedir restriction-bypass
  vulnerability. Successful exploits could allow an attacker to
  access files in unauthorized locations.

  This vulnerability would be an issue in shared-hosting
  configurations where multiple users can create and execute
  arbitrary PHP script code, with the safe_mode and open_basedir
  restrictions assumed to isolate the users from each other.

  PHP 5.2.9 is vulnerable; other versions may also be affected.";


if(description)
{
  script_id(100145);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-16 19:20:22 +0200 (Thu, 16 Apr 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_bugtraq_id(34475);
  script_name("PHP cURL 'safe_mode' and 'open_basedir' Restriction-Bypass Vulnerability");
  desc = "

  Summary:
  " + tag_summary;


  script_description(desc);
  script_summary("Determine if php is vulnerable Restriction-Bypass");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("php/installed");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34475");
  exit(0);
}


include("version_func.inc");
include("global_settings.inc");

## This nvt is prone to FP
if(report_paranoia < 2){
  exit(0);
}

phpPort = get_kb_item("Services/www");
if(!phpPort){
  exit(0);
}

phpVer = get_kb_item("www/" + phpPort + "/PHP");
if(!phpVer){
  exit(0);
}

# Check PHP version 5.2.9
if(version_is_equal(version:phpVer, test_version:"5.2.9")){
  security_warning(phpPort);
}
