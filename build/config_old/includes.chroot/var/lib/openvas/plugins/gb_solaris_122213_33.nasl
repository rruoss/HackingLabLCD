###############################################################################
# OpenVAS Vulnerability Test
#
# Solaris Update for GNOME Desktop 122213-33
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_affected = "GNOME Desktop on solaris_5.10_x86";
tag_insight = "The remote host is missing a patch containing a security fix,
  which affects the following component(s): 
  GNOME Desktop
  For more information please visit the below reference link.";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_id(855627);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-09-23 10:48:35 +0200 (Wed, 23 Sep 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "SUNSolve", value: "122213-33");
  script_cve_id("CVE-2007-2949", "CVE-2007-2356", "CVE-2006-3404");
  script_name("Solaris Update for GNOME Desktop 122213-33");
  desc = "

  Vulnerability Insight:
  " + tag_insight + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  script_xref(name : "URL" , value : "http://sunsolve.sun.com/search/document.do?assetkey=1-21-122213-33-1");

  script_description(desc);
  script_summary("Check for the Version of GNOME Desktop");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Solaris Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_require_keys("ssh/login/solosversion");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("solaris.inc");

release = get_kb_item("ssh/login/solosversion");

if(release == NULL){
  exit(0);
}

if(solaris_check_patch(release:"5.10", arch:"i386", patch:"122213-33", package:"SUNWgnome-session-share SUNWgnome-img-editor SUNWgnome-desktop-prefs SUNWgnome-libs-root SUNWPython SUNWgnome-panel-devel SUNWgnome-img-viewer-share SUNWgnome-panel-share SUNWgnome-panel SUNWgnome-themes-share SUNWgnome-display-mgr-share SUNWgnome-panel-root SUNWgnome-session SUNWgnome-libs SUNWgnome-libs-share SUNWgnome-display-mgr SUNWgnome-desktop-prefs-share SUNWgnome-file-mgr-share SUNWgnome-display-mgr-root SUNWgnome-file-mgr-root SUNWgnome-file-mgr SUNWgnome-img-editor-share") < 0)
{
  security_hole(0);
  exit(0);
}