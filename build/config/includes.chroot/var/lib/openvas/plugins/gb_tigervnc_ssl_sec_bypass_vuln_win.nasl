###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tigervnc_ssl_sec_bypass_vuln_win.nasl 13 2013-10-27 12:16:33Z jan $
#
# TigerVNC SSL Certificate Validation Security Bypass Vulnerability (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation allows attackers to perform man-in-the-middle attacks
  or impersonate trusted servers, which will aid in further attacks.
  Impact Level: Application";
tag_affected = "TigerVNC version 1.1beta1";
tag_insight = "The flaw is caused by improper verification of server's X.509 certificate,
  which allows man-in-the-middle attackers to spoof a TLS VNC server via an
  arbitrary certificate.";
tag_solution = "No solution or patch is available as of 6th June, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://tigervnc.org/";
tag_summary = "This host is installed with TigerVNC and is prone to security
  bypass vulnerability.";

if(description)
{
  script_id(801898);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-13 15:28:04 +0200 (Mon, 13 Jun 2011)");
  script_cve_id("CVE-2011-1775");
  script_bugtraq_id(47738);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"risk_factor", value:"High");
  script_name("TigerVNC SSL Certificate Validation Security Bypass Vulnerability (Windows)");
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
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=702470");
  script_xref(name : "URL" , value : "http://www.mail-archive.com/tigervnc-devel@lists.sourceforge.net/msg01345.html");

  script_description(desc);
  script_summary("Check for the version of TigerVNC");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_tigervnc_detect_win.nasl");
  script_require_keys("TigerVNC/Win/Ver");
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

## Get version from KB
ver = get_kb_item("TigerVNC/Win/Ver");
if(ver)
{
  ## Check for TigerVNC Version 1.1beta1 (1.0.90)
  if(version_is_equal(version:ver, test_version:"1.0.90")){
    security_hole(0);
  }
}
