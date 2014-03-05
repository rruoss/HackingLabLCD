# OpenVAS Vulnerability Test
# $Id: surgeldap_file_disclosure.nasl 17 2013-10-27 14:01:43Z jan $
# Description: File Disclosure in SurgeLDAP
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
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
tag_summary = "There is a vulnerability in the current version of SurgeLDAP
that allows an attacker to retrieve arbitrary files
from the webserver that reside outside the bounding HTML root
directory.";

# From: Dr_Insane
# Subject: SurgeLDAP 1.0g Web service user.cgi File retrieval
# Date: April 13, 2004
# Http://members.lycos.co.uk/r34ct/

if(description)
{
  script_id(12211);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-2253");
  script_bugtraq_id(10103);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  name = "File Disclosure in SurgeLDAP";
  script_name(name);
 
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
 
  summary = "Detect SurgeLDAP File Disclosure";
  script_summary(summary);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright("This script is Copyright (C) 2004 Noam Rathaus");

  family = "General";
  script_family(family);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 6680);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);

function check_dir(path)
{
 req = http_get(item:string(path, "/user.cgi?cmd=show&page=/../../../boot.ini"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if ( res == NULL ) exit(0);
 find = string("[boot loader]");
 if ( find >< res )
 {
  security_warning(port);
  exit(0);
 }
}

foreach dir (cgi_dirs()) check_dir(path:dir);
