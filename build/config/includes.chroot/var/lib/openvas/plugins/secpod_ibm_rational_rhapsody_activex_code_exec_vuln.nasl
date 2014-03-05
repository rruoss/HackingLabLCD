###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ibm_rational_rhapsody_activex_code_exec_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# IBM Rational Rhapsody BB FlashBack SDK ActiveX Control Remote Code Execution VUlnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attacker to execution of arbitrary code.
  Impact Level: Application";
tag_affected = "IBM Rational Rhapsody version prior to 7.6.1";
tag_insight = "The flaws are due to erros in the BB FlashBack ActiveX control
  (BBFlashBack.Recorder.dll) within the FBRecorder class when handling the
  'Start()', 'PauseAndSave()', 'InsertMarker()', 'InsertSoundToFBRAtMarker()'
  and 'TestCompatibilityRecordMode()' methods.";
tag_solution = "Upgrade to IBM Rational Rhapsody versions 7.6.1 or later
  For updates refer to http://www-01.ibm.com/support/docview.wss?uid=swg21576352";
tag_summary = "This host is installed with IBM Rational Rhapsody and is prone to
  remote code execution vulnerabilities.";

if(description)
{
  script_id(902655);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2011-1388", "CVE-2011-1391", "CVE-2011-1392");
  script_bugtraq_id(51184);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-12-29 15:57:58 +0530 (Thu, 29 Dec 2011)");
  script_name("IBM Rational Rhapsody BB FlashBack SDK ActiveX Control Remote Code Execution VUlnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47310");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47286");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/71803");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/47310");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21576352");

  script_description(desc);
  script_summary("Check for the version of IBM Rational Rhapsody");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("General");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Get version from Registry
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  ibmrrName = registry_get_sz(key:key + item, item:"DisplayName");
  if("IBM Rational Rhapsody" >< ibmrrName)
  {
    ibmrrVer = registry_get_sz(key:key + item, item:"DisplayVersion");

    if(ibmrrVer != NULL)
    {
      ## Check for IBM Rational Rhapsody version
      if(version_is_less(version:ibmrrVer, test_version:"7.6.1"))
      {
        security_hole(0);
        exit(0);
      }
    }
  }
}