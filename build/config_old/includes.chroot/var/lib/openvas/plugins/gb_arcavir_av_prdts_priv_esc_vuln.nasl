###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_arcavir_av_prdts_priv_esc_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# ArcaVir AntiVirus Products Privilege Escalation Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will let the attacker pass kernel addresses as the
  arguments to the driver and overwrite an arbitrary address in the kernel space
  through a specially crafted IOCTL.

  Impact level: System";

tag_affected = "ArcaBit 2009 Home Protection prior to 9.4.3204.9
  ArcaVir 2009 System Protection prior to 9.4.3203.9
  ArcaVir 2009 Internet Security prior to 9.4.3202.9
  ArcaBit ArcaVir 2009 Antivirus Protection prior to 9.4.3201.9";
tag_insight = "This flaw is due to vulnerability in ps_drv.sys driver, which allows any users
  to open the device '\\Device\\ps_drv' and issue IOCTLs with a buffering mode of
  METHOD_NEITHER.";
tag_solution = "Apply the security updates accordingly.
  http://www.arcabit.pl";
tag_summary = "This host is running ArcaVir AntiVirus Products and is prone to Privilege
  Escalation Vulnerability.";

if(description)
{
  script_id(800720);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-06-04 07:18:37 +0200 (Thu, 04 Jun 2009)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_bugtraq_id(35100);
  script_cve_id("CVE-2009-1824");
  script_name("ArcaVir AntiVirus Products Privilege Escalation Vulnerability");
  desc = "

  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35260");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8782");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/1428");
  script_xref(name : "URL" , value : "http://ntinternals.org/ntiadv0814/ntiadv0814.html");

  script_description(desc);
  script_summary("Check for the version of ArcaVir AntiVirus Products");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_arcavir_av_prdts_detect.nasl");
  script_require_keys("ArcaVir/AntiVirus/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
  }
  exit(0);
}


include("version_func.inc");

# ArcaVir AntiVirus Product version prior to 9.4.3201.9
arvaavVer = get_kb_item("ArcaVir/AntiVirus/Ver");
if(arvaavVer != NULL)
{
  if(version_is_less(version:arvaavVer, test_version:"9.4.3201.9")){
    security_hole(0);
  }
}
