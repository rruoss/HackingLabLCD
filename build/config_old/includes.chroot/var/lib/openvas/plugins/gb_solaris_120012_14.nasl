###############################################################################
# OpenVAS Vulnerability Test
#
# Solaris Update for kernel 120012-14
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
tag_affected = "kernel on solaris_5.10_x86";
tag_insight = "The remote host is missing a patch containing a security fix,
  which affects the following component(s): 
  kernel
  For more information please visit the below reference link.";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_id(855205);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-06-03 12:31:50 +0200 (Wed, 03 Jun 2009)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "SUNSolve", value: "120012-14");
  script_cve_id("CVE-2007-0957", "CVE-2006-0225");
  script_name( "Solaris Update for kernel 120012-14");
  desc = "

  Vulnerability Insight:
  " + tag_insight + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  script_xref(name : "URL" , value : "http://sunsolve.sun.com/search/document.do?assetkey=1-21-120012-14-1");

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

if(solaris_check_patch(release:"5.10", arch:"i386", patch:"120012-14", package:"SUNWcpc.i SUNWsshcu SUNWpcmci SUNWnge SUNWcnetr SUNWdhcsu SUNWrcmdc SUNWperl584usr SUNWixgb SUNWpsu SUNWfss SUNWatfsu SUNWpmu SUNWlldap SUNWipfr SUNWudapltu SUNWzoner SUNWarc SUNWipfu SUNWfmd SUNWintgige SUNWscpu SUNWbtool SUNWxge SUNWsra SUNWperl584core SUNWbart SUNWkrbu SUNWsmapi SUNWtavor SUNWipfh SUNWmdb SUNWzfsu SUNWsndmr SUNWaudit SUNWncar SUNWpapi SUNWsshdu SUNWsndmu SUNWpppdu SUNWnfssu SUNWdhcm SUNWkdcu SUNWpsdir SUNWpool SUNWxcu4 SUNWudapltr SUNWdtrc SUNWopenssl-libraries SUNWcsl SUNWcpcu SUNWses SUNWsadmi SUNWvolu SUNWib SUNWkey SUNWnisu SUNWos86r SUNWtoo SUNWdmgtu SUNWusbu SUNWypu SUNWpoolr SUNWftduu SUNWppm SUNWuksp SUNWusb SUNWzfsr SUNWroute SUNWckr SUNWcsr SUNWdoc SUNWaudh SUNWrge SUNWtecla SUNWmdbr SUNWpcu SUNWzfskr SUNWarcr SUNWrcapu SUNWwbsup SUNWhea SUNWcakr.i SUNWqos SUNWntpu SUNWnfsckr SUNWdtrp SUNWlibsasl SUNWcslr SUNWippcore SUNWrmodr SUNWsshu SUNWcsu SUNWnfscu SUNWesu SUNWcsd SUNWipplr SUNWpsm-lpd SUNWuprl SUNWzoneu SUNWipplu SUNWrcapr SUNWdfbh SUNWftdur SUNWauda") < 0)
{
  security_hole(0);
  exit(0);
}