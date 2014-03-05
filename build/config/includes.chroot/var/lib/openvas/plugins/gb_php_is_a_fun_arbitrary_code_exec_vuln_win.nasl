###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_is_a_fun_arbitrary_code_exec_vuln_win.nasl 13 2013-10-27 12:16:33Z jan $
#
# PHP 'is_a()' Function Remote Arbitrary Code Execution Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_solution = "No solution or patch is available as of 8th November, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://php.net/downloads.php

  Workaround:
  Apply the workaround for PHP from below link,
  http://www.byte.nl/blog/2011/09/23/security-bug-in-is_a-function-in-php-5-3-7-5-3-8/

  *****
  NOTE : Ignore this warning, if above workaround has been applied.
  *****";

tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary PHP
  code by including arbitrary files from remote resources.
  Impact Level: Application/System";
tag_affected = "PHP Version 5.3.7 and 5.3.8 on windows.";
tag_insight = "The flaw is due to error in 'is_a()' function. It receives strings as
  first argument, which can lead to the '__autoload()' function being called
  unexpectedly and do not properly verify input in their '__autoload()'
  function, which leads to an unexpected attack vectors.";
tag_summary = "This host is installed with PHP and is prone to remote arbitrary
  code execution vulnerability.";

if(description)
{
  script_id(802504);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-11-08 13:11:11 +0530 (Tue, 08 Nov 2011)");
  script_cve_id("CVE-2011-3379");
  script_bugtraq_id(49754);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("PHP 'is_a()' Function Remote Arbitrary Code Execution Vulnerability (Windows)");
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

  script_xref(name : "URL" , value : "http://secunia.com/advisories/46107/");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=741020");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/519770/30/0/threaded");
  script_xref(name : "URL" , value : "http://www.byte.nl/blog/2011/09/23/security-bug-in-is_a-function-in-php-5-3-7-5-3-8/");

  script_description(desc);
  script_summary("Check for the version of PHP");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_php_detect_win.nasl");
  script_require_keys("PHP/Ver/win");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("version_func.inc");

## Get version from KB
phpVer = get_kb_item("PHP/Ver/win");

if(phpVer != NULL)
{
  ##Check for PHP version
  if(version_is_equal(version:phpVer, test_version:"5.3.7") ||
     version_is_equal(version:phpVer, test_version:"5.3.8")){
    security_hole(0);
  }
}
