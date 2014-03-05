###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_django_dir_traversal_vuln_lin.nasl 15 2013-10-27 12:49:54Z jan $
#
# Django Directory Traversal Vulnerability (Linux)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
tag_impact = "Successful exploitation will let the attacker launch directory traversal
  attack and read arbitrary files via crafted URLs.
  Impact Level: Application";
tag_affected = "Django 0.96 before 0.96.4 and 1.0 before 1.0.3 on Linux";
tag_insight = "Admin media handler in core/servers/basehttp.py does not properly map
  URL requests to expected 'static media files,' caused via a
  carefully-crafted URL whcih can cause the development server to serve any
  file to which it has read access.";
tag_solution = "Upgrade to Django 0.96.4 or 1.0.3 later.
  http://www.djangoproject.com/download/";
tag_summary = "This host has Django installed and is prone to Directory Traversal
  Vulnerability.";

if(description)
{
  script_id(800924);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-08-11 07:36:16 +0200 (Tue, 11 Aug 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-2659");
  script_bugtraq_id(35859);
  script_name("Django Directory Traversal Vulnerability (Linux)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36137");
  script_xref(name : "URL" , value : "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=539134");
  script_xref(name : "URL" , value : "http://www.djangoproject.com/weblog/2009/jul/28/security/");

  script_description(desc);
  script_summary("Checks the version of Django");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_django_detect_lin.nasl");
  script_require_keys("Django/Linux/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("version_func.inc");

djangoVer = get_kb_item("Django/Linux/Ver");
if(!djangoVer){
  exit(0);
}

# Grep for Django version < 0.9.64 or 1.0 < 1.0.3
if(version_is_less(version:djangoVer, test_version:"0.96.4") ||
   version_in_range(version:djangoVer, test_version:"1.0",
                                      test_version2:"1.0.2")){
  security_warning(0);
}
