###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apache_apr-utils_mult_dos_vuln_jun09.nasl 15 2013-10-27 12:49:54Z jan $
#
# Apache APR-Utils Multiple Denial of Service Vulnerabilities
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_impact = "Attackers can exploit these issues to crash the application
  resulting into a denial of service conditions.
  Impact Level: Application";
tag_affected = "Apache APR-Utils before 1.3.5 on Linux.";
tag_insight = "The Flaws are  due to,
  - An integer underflow Error in the apr_strmatch_precompile() function
    in 'strmatch/apr_strmatch.c', while processing malicious data.
  - A Off-by-one error in the apr_brigade_vprintf function on big-endian
    platform while processing crafted input.";
tag_solution = "Apply the patches or upgrade to Apache APR-Utils 1.3.5 or later.
  http://apr.apache.org/download.cgi";
tag_summary = "The host is installed with Apache APR-Utils and is prone to
  Multiple Denial of Service Vulnerabilities.";

if(description)
{
  script_id(900572);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-06-24 07:17:25 +0200 (Wed, 24 Jun 2009)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-1956", "CVE-2009-0023");
  script_bugtraq_id(35221, 35251);
  script_name("Apache APR-Utils Multiple Denial of Service Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/50964");
  script_xref(name : "URL" , value : "http://www.apache.org/dist/apr/CHANGES-APR-UTIL-1.3");

  script_description(desc);
  script_summary("Check for the version of Apache APR-Utils");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_apache_apr-utils_detect.nasl");
  script_require_keys("Apache/APR-Utils/Ver");
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

utilsVer = get_kb_item("Apache/APR-Utils/Ver");
if(!utilsVer){
  exit(0);
}

if(version_is_less(version:utilsVer, test_version:"1.3.5")){
  security_hole(0);
}
