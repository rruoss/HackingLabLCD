###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_insecure_lib_loading_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Microsoft Windows Insecure Library Loading Vulnerability (2269637)
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
tag_solution = "No solution or patch is available as of 10th, August, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://technet.microsoft.com/en-us/security/default.aspx

  Workaround:
  Apply workaround from below link,
  http://support.microsoft.com/kb/2264107";

tag_impact = "Successful exploitation will allow attacker to remotely execute arbitrary
  code in the context of the user running the vulnerable application when the
  user opens a file from an untrusted location.
  Impact Level: System";
tag_affected = "Microsoft Windows 7 Service Pack 1 and prior.
  Microsoft Windows XP Service Pack 3 and prior.
  Microsoft Windows 2003 Service Pack 2 and prior.
  Microsoft Windows Vista Service Pack 2 and prior.
  Microsoft Windows Server 2008 Service Pack 2 and prior.";
tag_insight = "The flaw is due to the applications installed on windows, passes an
  insufficiently qualified path of '.dll' files when loading an external
  library.";
tag_summary = "This host is missing a critical security update according to Microsoft
  Security Advisory (2269637).

  This NVT has been replaced by NVT secpod_ms12-014.nasl
  (OID:1.3.6.1.4.1.25623.1.0.902792).";

if(description)
{
  script_id(802136);
  script_version("$Revision: 13 $");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-11 06:41:03 +0200 (Thu, 11 Aug 2011)");
  script_cve_id("CVE-2010-3337");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Microsoft Windows Insecure Library Loading Vulnerability (2269637)");
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

  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2264107");
  script_xref(name : "URL" , value : "http://forums.cnet.com/7723-6132_102-407460.html");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/advisory/2269637.mspx");

  script_description(desc);
  script_summary("Check for the presence of registry key");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}

exit(66); ## This NVT is deprecated as addressed in secpod_ms12-014.nasl

include("smb_nt.inc");

key = "SYSTEM\CurrentControlSet\Control\Session Manager";
if(registry_key_exists(key:key))
{
  ## Checking the item CWDIllegalInDllSearch, added after applying workaround
  value = registry_get_dword(key:key, item:"CWDIllegalInDllSearch");
  if(isnull(value)){
      security_hole(0);
  }
}
