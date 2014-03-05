###############################################################################
# OpenVAS Vulnerability Test
#
# Solaris Update for kernel 118833-36
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
tag_affected = "kernel on solaris_5.10_sparc";
tag_insight = "The remote host is missing a patch containing a security fix,
  which affects the following component(s): 
  kernel
  For more information please visit the below reference link.";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_id(855619);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-06-03 12:28:12 +0200 (Wed, 03 Jun 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "SUNSolve", value: "118833-36");
  script_name( "Solaris Update for kernel 118833-36");
  desc = "

  Vulnerability Insight:
  " + tag_insight + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  script_xref(name : "URL" , value : "http://sunsolve.sun.com/search/document.do?assetkey=1-21-118833-36-1");

  script_description(desc);
  script_summary("Check for the Version of kernel");
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

if(solaris_check_patch(release:"5.10", arch:"sparc", patch:"118833-36", package:"SUNWcakr.u SUNWpcmci SUNWcnetr SUNWrcmdc SUNWpsu SUNWatfsu SUNWscplp SUNWsacom SUNWipfr SUNWaudd SUNWudapltu SUNWarc SUNWipfu SUNWintgige SUNWscpu SUNWbtool SUNWxge SUNWidn.u SUNWbart SUNWkrbu SUNWdrcr.u SUNWsckmu.u SUNWsmapi SUNWtavor SUNWopenssl-commands SUNWipfh SUNWmdb SUNWsndmr SUNWrpcib SUNWncar SUNWcakr.us SUNWmddr SUNWcart200.v SUNWcpr.u SUNWkvm.u SUNWsndmu SUNWpppdu SUNWnfssu SUNWmdr SUNWkvm.v SUNWkvm.us FJSVhea SUNWxcu4 SUNWudapltr SUNWdtrc SUNWxcu6 SUNWusbs SUNWopenssl-libraries SUNWcsl FJSVmdbr SUNWcpcu SUNWses SUNWugen SUNWvolu SUNWib SUNWkey SUNWnisu SUNWuedg SUNWtoo SUNWsckmr SUNWdrr.u FJSVpiclu SUNWkvmt200.v SUNWpl5v SUNWusbu SUNWefc.u SUNWpiclu SUNWnfssr SUNWppm SUNWuksp SUNWcakr.v SUNWusb SUNWvolr SUNWcti2.u SUNWdrr.us SUNWroute SUNWckr SUNWcsr SUNW1394 SUNWaudh SUNWkrbr SUNWefcl SUNWcvcr.u SUNWmdbr SUNWpd SUNWpcu SUNWsbp2 SUNWarcr SUNWmdu SUNWdcsu FJSVmdb SUNWwbsup SUNWhea SUNWqos SUNWnfsckr SUNWdtrp SUNWnfsskr SUNWatfsr SUNWcslr SUNWwrsd.u SUNWdcsr SUNWcsu SUNWust1.v SUNWcar.u SUNWnfscu SUNWesu SUNWcsd SUNWfruip.u SUNWssad SUNWpcmem SUNWpdu SUNWuprl SUNWluxl SUNWefc.us SUNWdfbh SUNWnfscr SUNWscsa1394 SUNWwrsm.u SUNWftdur SUNWudfr SUNWipoib") < 0)
{
  security_hole(0);
  exit(0);
}
