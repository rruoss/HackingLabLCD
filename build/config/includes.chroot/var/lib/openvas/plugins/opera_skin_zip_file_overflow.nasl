# OpenVAS Vulnerability Test
# $Id: opera_skin_zip_file_overflow.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Opera skin zip file buffer overflow vulnerability
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
# Date: 03/12/2009 Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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
tag_summary = "The remote host is using Opera - an alternative web browser.
  This version is vulnerable to a security weakness.

  A problem has been identified in the handling of zipped skin
  files by Opera. Because of this, it may be possible for an attacker
  to gain unauthorized access to a system using the vulnerable browser.";

tag_solution = "Install Opera 7.23 or newer.";

# Ref: Jouko Pynnonen

if(description)
{
  script_id(14250);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(9089);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Opera skin zip file buffer overflow vulnerability");
  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;

  script_description(desc);
  script_summary("Determines the version of Opera.exe");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Windows");
  script_dependencies("secpod_opera_detection_win_900036.nasl");
  script_require_keys("Opera/Win/Version");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("version_func.inc");

OperaVer = get_kb_item("Opera/Win/Version");
if(!OperaVer){
  exit(0);
}

if(version_is_less_equal(version:OperaVer, test_version:"7.22")){
  security_hole(0);
}
