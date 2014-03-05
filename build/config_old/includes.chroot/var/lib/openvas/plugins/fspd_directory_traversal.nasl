# OpenVAS Vulnerability Test
# $Id: fspd_directory_traversal.nasl 17 2013-10-27 14:01:43Z jan $
# Description: FSP Suite Directory Traversal Vulnerability
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
tag_summary = "The FSP Suite (daemon) has been found to improperly filter out
paths with trailing / or starting with /. This would allow an attacker
access to files that reside outside the bounding FSP root diretory.";

if(description)
{
 script_id(11988);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2003-1022");
 script_bugtraq_id(9377);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 name = "FSP Suite Directory Traversal Vulnerability";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);

 summary = "FSPD Detection";
 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
 family = "Remote file access";
 script_family(family);
 script_dependencies("fsp_detection.nasl");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

debug = 0;

# This is UDP based protocol ...

banners = get_kb_list("fsp/banner/*");
if ( isnull(banners) ) exit(0);

foreach k (keys(banners))
{
 port   = int(k - "fsp/banner/");
 banner = banners[k];

 if (egrep(string:banner, pattern:"fspd (2\.8\.1b1[0-7]|2\.8\.0|2\.[0-7]\.|[0-1]\.)"))
 {
  security_hole(port:port, protocol:"udp");
  exit(0);
 }
}
