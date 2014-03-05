###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_tnftpd_csrf_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# tnftpd 'ftp://' Cross-Site Request Forgery Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will let the attacker execute arbitrary code to
  perform CSRF attacks, Web cache poisoning, and other malicious activities.
  Impact Level: Application/Network";
tag_affected = "NetBSD, tnftpd Version prior to 20080929";
tag_insight = "The flaw is due to the application truncating an overly long FTP
  command and improperly interpreting the remainder string as a new FTP
  command. This can be exploited via unknown vectors, probably involving a
  crafted 'ftp://' link to a tnftpd server.";
tag_solution = "Upgrade to tnftpd version 20080929 or later,
  ftp://ftp.netbsd.org/pub/NetBSD/misc/tnftp/";
tag_summary = "The host is running tnftpd server and is prone to Cross-Site Request
  Forgery vulnerability.";

if(description)
{
  script_id(901006);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-08-27 13:43:20 +0200 (Thu, 27 Aug 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2008-7016");
  script_name("tnftpd 'ftp://' Cross-Site Request Forgery Vulnerability");
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


  script_description(desc);
  script_summary("Check for the version of tnftpd");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("FTP");
  script_dependencies("secpod_tnftpd_detect.nasl");
  script_require_keys("tnftpd/ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://secunia.com/advisories/31958");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/45534");
  script_xref(name : "URL" , value : "http://freshmeat.net/projects/tnftpd/?branch_id=14355&amp;release_id=285654");
  exit(0);
}


include("version_func.inc");

tnftpVer = get_kb_item("/tnftpd/Ver");

if(tnftpVer != NULL)
{
  if(version_is_less(version:tnftpVer, test_version:"20080929")){
    security_hole(21);
  }
}