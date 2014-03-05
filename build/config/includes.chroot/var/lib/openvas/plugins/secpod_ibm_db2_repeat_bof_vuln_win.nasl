###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ibm_db2_repeat_bof_vuln_win.nasl 14 2013-10-27 12:33:37Z jan $
#
# IBM DB2 REPEAT Buffer Overflow and TLS Renegotiation Vulnerabilities (Win)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attacker to cause a denial of service or
  to bypass security restrictions.
  Impact Level: System/Application";
tag_affected = "IBM DB2 version 9.1 prior to FP9";
tag_insight = "The flaws are due to:
  - Buffer overflow error within the scalar function 'REPEAT', which could allow
    malicious users to cause a vulnerable server to crash.
  - An error in the 'TLS' implementation while handling session 're-negotiations'
    which can be exploited to insert arbitrary plaintext into an existing TLS
    session via Man-in-the-Middle (MitM) attacks.";
tag_solution = "Update IBM DB2 9.1 FP9,
  For updates refer to http://www-01.ibm.com/support/docview.wss?rs=71&uid=swg27007053";
tag_summary = "The host is installed with IBM DB2 and is prone to buffer overflow
  and TLS Renegotiation vulnerabilities.";

if(description)
{
  script_id(902175);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-04-30 15:20:35 +0200 (Fri, 30 Apr 2010)");
  script_cve_id("CVE-2010-1560");
  script_name("IBM DB2 REPEAT Buffer Overflow and TLS Renegotiation Vulnerabilities (Win)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39500");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/0982");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21426108");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg1IC65922");

  script_description(desc);
  script_summary("Check for the version of IBM DB2");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Databases");
  script_dependencies("secpod_ibm_db2_detect_win_900218.nasl");
  script_require_keys("Win/IBM-db2/Ver");
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

ibmVer = get_kb_item("Win/IBM-db2/Ver");
if(!ibmVer){
  exit(0);
}

# Check for IBM DB2 Version 9.1 before 9.1 FP9  (IBM DB2 9.1 FP 9 = 9.1.900.215)
if(version_in_range(version:ibmVer, test_version:"9.1", test_version2:"9.1.900.214")){
  security_warning(0);
}
