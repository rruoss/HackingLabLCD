###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ftpshell_client_pasv_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# FTPShell Client PASV Command Buffer Overflow Vulnerability
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
tag_impact = "Successful exploitation will let the user execute arbitrary code and crash
  the application to cause denial of service.";
tag_affected = "FTPShell Client 4.1 RC2 and prior.";
tag_insight = "A buffer overflow error occurs due to improper bounds checking when handling
  overly long PASV messages sent by the server.";
tag_solution = "No solution or patch is available as of 30th September, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.ftpshell.com/";
tag_summary = "This host is running FTPShell Client and is prone to Buffer
  Overflow vulnerability.";

if(description)
{
  script_id(900962);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-10-01 12:15:29 +0200 (Thu, 01 Oct 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-3364");
  script_bugtraq_id(36327);
  script_name("FTPShell Client PASV Command Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36628");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9613");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/53126");

  script_description(desc);
  script_summary("Check for the version of FTPShell Client");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_ftpshell_client_detect.nasl");
  script_require_keys("FTPShell/Client/Ver");
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

shellVer = get_kb_item("FTPShell/Client/Ver");
if(isnull(shellVer)){
  exit(0);
}

if(version_is_less_equal(version:shellVer, test_version:"4.1.RC2")){
  security_hole(0);
}
