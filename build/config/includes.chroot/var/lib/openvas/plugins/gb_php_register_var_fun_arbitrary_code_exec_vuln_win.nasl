###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_register_var_fun_arbitrary_code_exec_vuln_win.nasl 12 2013-10-27 11:15:33Z jan $
#
# PHP 'php_register_variable_ex()' Remote Code Execution Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary PHP
  code on the system.
  Impact Level: System/Application";
tag_affected = "PHP Version 5.3.9 on windows.";
tag_insight = "The flaw is due to a logic error within the 'php_register_variable_ex()'
  function in php_variables.c when hashing form posts and updating a hash table,
  which can be exploited to execute arbitrary code.";
tag_solution = "Upgrade to PHP Version 5.3.10 or later,
  For updates refer to http://php.net/downloads.php";
tag_summary = "This host is installed with PHP and is prone to remote arbitrary
  code execution vulnerability.";

if(description)
{
  script_id(802590);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-0830");
  script_bugtraq_id(51830);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-02-10 11:24:19 +0530 (Fri, 10 Feb 2012)");
  script_name("PHP 'php_register_variable_ex()' Remote Code Execution Vulnerability (Windows)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47806");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/72911");
  script_xref(name : "URL" , value : "http://www.php.net/ChangeLog-5.php#5.3.10");
  script_xref(name : "URL" , value : "http://www.auscert.org.au/render.html?it=15408");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/cve/CVE-2012-0830");

  script_description(desc);
  script_summary("Check for the version of PHP");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_php_detect_win.nasl");
  script_require_keys("PHP/Ver/win");
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

phpVer = NULL;

## Get version from KB
phpVer = get_kb_item("PHP/Ver/win");

if(!isnull(phpVer))
{
  ##Check for PHP version
  if(version_is_equal(version:phpVer, test_version:"5.3.9")){
    security_hole(0);
  }
}
