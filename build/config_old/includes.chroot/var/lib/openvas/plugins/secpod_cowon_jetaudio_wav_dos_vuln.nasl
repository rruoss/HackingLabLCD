###############################################################################
# OpenVAS Vulnerabilities Test
# $Id: secpod_cowon_jetaudio_wav_dos_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# COWON Media Center JetAudio .wav File Denial Of Service Vulnerability
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
tag_summary = "This host has COWON Media Center JetAudio installed and is prone
  to Denial of Service vulnerability.

  Vulnerabilities Insight:
  An error occurs while parsing a .wav file containing an overly long string
  at the end.";

tag_impact = "Attackers can exploit this issue to corrupt memory and cause the application
  to crash.
  Impact Level: Application";
tag_affected = "COWON Media Center JetAudio 7.5.3 on Windows.";
tag_solution = "Upgrade to COWON Media Center JetAudio version 8.0.6 or later
  For updates refer to http://www.jetaudio.com/";

if(description)
{
  script_id(900977);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-11-20 06:52:52 +0100 (Fri, 20 Nov 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-3948");
  script_name("COWON Media Center JetAudio .wav File Denial Of Service Vulnerability");
  desc = "
  Summary:
  " + tag_summary + "
  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9139");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/51697");

  script_description(desc);
  script_summary("Check for the version of COWON Media Center JetAudio");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_cowon_jetaudio_detect.nasl");
  script_require_keys("JetAudio/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("version_func.inc");

jaVer = get_kb_item("JetAudio/Ver");

if(jaVer != NULL)
{
  # Check if the version is equal to 7.5.3 => 7.5.3.15
  if(version_is_equal(version:jaVer, test_version:"7.5.3.15")){
    security_warning(0);
  }
}
