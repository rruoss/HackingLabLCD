###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_samba_dos_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Samba winbind Daemon Denial of Service Vulnerability
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
tag_impact = "Successful exploitation will let the attacker crash the application.

  Impact level: Application";

tag_affected = "Samba version prior to 3.0.32";
tag_insight = "This flaw is due to a race condition in the winbind daemon which allows
  remote attackers to cause denial of service through unspecified vectors
  related to an unresponsive child process.";
tag_solution = "Upgrade to the latest version 3.0.32
  http://us1.samba.org/samba";
tag_summary = "This host is installed with Samba for Linux and is prone to
  Winbind daemon Denial of Service Vulnerability.";

if(description)
{
  script_id(800711);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-28 07:14:08 +0200 (Thu, 28 May 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2008-6800");
  script_name("Samba winbind Daemon Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://wiki.rpath.com/wiki/Advisories:rPSA-2008-0308");
  script_xref(name : "URL" , value : "http://www.samba.org/samba/history/samba-3.0.32.html");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/497941/100/0/threaded");

  script_description(desc);
  script_summary("Check for the version of Samba");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_samba_detect.nasl");
  script_require_keys("Samba/Version");
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

sambaVer = get_kb_item("Samba/Version");
sambaVer = ereg_replace(pattern:"-", string:sambaVer, replace:".");
sambaVer = ereg_replace(pattern:"\.([a-z|A-Z].*)", string:sambaVer, replace:"");
if(sambaVer == NULL){
  exit(0);
}

# Grep for Samba version prior to 3.0.32
if(version_is_less(version:sambaVer, test_version:"3.0.32")){
  security_warning(0);
}
