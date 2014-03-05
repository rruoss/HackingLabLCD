# OpenVAS Vulnerability Test
# $Id: opera_remote_location_object_flaw.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Opera remote location object cross-domain scripting vulnerability
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
# uPDATED: 02/12/2009 Antu Sanadi <santu@secpod.com>
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
tag_summary = "The remote host contains a web browser that is affected by
  multiple flaws.

  Description :
  The remote host is using Opera, an alternative web browser.
  This version of Opera on the remote host fails to block write access to
  the 'location' object.  This could allow a user to create a specially
  crafted URL to overwrite methods within the 'location' object that would
  execute arbitrary code in a user's browser within the trust relationship
  between the browser and the server, leading to a loss of confidentiality
  and integrity.";

tag_solution = "Upgrade to Opera 7.54 or newer.";

# Ref: GreyMagic Software

if(description)
{
  script_id(14261);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-2570");
  script_bugtraq_id(10873);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Opera remote location object cross-domain scripting vulnerability");
  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;  script_description(desc);
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
  script_xref(name : "URL" , value : "http://www.greymagic.com/security/advisories/gm008-op/");
  script_xref(name : "URL" , value : "http://www.opera.com/docs/changelogs/windows/754/");
  exit(0);
}


include("version_func.inc");

OperaVer = get_kb_item("Opera/Win/Version");
if(!OperaVer){
  exit(0);
}

if(version_is_less_equal(version:OperaVer, test_version:"7.53")){
  security_warning(0);
}
