###############################################################################
# OpenVAS Vulnerability Test
#
# Solaris Update for Kernel 122300-44
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
tag_affected = "Kernel on solaris_5.9_sparc";
tag_insight = "The remote host is missing a patch containing a security fix,
  which affects the following component(s): 
  Kernel
  For more information please visit the below reference link.";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_id(855780);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-10-13 15:16:45 +0200 (Tue, 13 Oct 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "SUNSolve", value: "122300-44");
  script_cve_id("CVE-2008-1483", "CVE-2006-3738", "CVE-2006-4343", "CVE-2006-4339", "CVE-2006-2937", "CVE-2006-2940");
  script_name("Solaris Update for Kernel 122300-44");
  desc = "

  Vulnerability Insight:
  " + tag_insight + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  script_xref(name : "URL" , value : "http://sunsolve.sun.com/search/document.do?assetkey=1-21-122300-44-1");

  script_description(desc);
  script_summary("Check for the Version of Kernel");
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

if(solaris_check_patch(release:"5.9", arch:"sparc", patch:"122300-44", package:"SUNWatfsu SUNWudfrx SUNWarc SUNWcarx.u SUNWrsg SUNWvolr SUNWcstl SUNWnfscx SUNWcslx SUNWsshdu SUNWcstlx SUNWrsgk SUNWpdx SUNWcsu SUNWnfssx SUNWnfscr SUNWcsxu SUNWnfssu SUNWaudit SUNWpd SUNWcsr SUNWsshdr SUNWefcx.us SUNWmdbx SUNWmdb SUNWdrrx.u SUNWvolu SUNWcar.u SUNWdrr.us SUNWudfr SUNWnfscu SUNWrsgx SUNWcar.m SUNWsshcu SUNWcar.us FJSVhea SUNWatfsr SUNWpiclu SUNWdrrx.us SUNWsshu SUNWcsl SUNWsshr SUNWdrr.u SUNWefcx.u SUNWnfssr SUNWcarx.us SUNWdrcrx.u SUNWhea") < 0)
{
  security_hole(0);
  exit(0);
}