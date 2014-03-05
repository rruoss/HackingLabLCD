###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_pango_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Pango Integer Buffer Overflow Vulnerability
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary code via
  a long glyph string, and can cause denial of service.
  Impact Level: Application";
tag_affected = "Pango version prior to 1.24.0";
tag_insight = "Error in pango_glyph_string_set_size function in pango/glyphstring.c file,
  which fails to perform adequate boundary checks on user-supplied data before
  using the data to allocate memory buffers.";
tag_solution = "Upgrade to pango version 1.24.0 or later
  http://ftp.acc.umu.se/pub/GNOME/sources/pango/";
tag_summary = "This host has installed with Pango and is prone to Integer Buffer
  Overflow vulnerability";

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.900644";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-22 08:49:17 +0200 (Fri, 22 May 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-1194");
  script_bugtraq_id(34870);
  script_name("Pango Integer Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35018");
  script_xref(name : "URL" , value : "http://www.debian.org/security/2009/dsa-1798");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2009/05/07/1");

  script_description(desc);
  script_summary("Check for the Version of Pango");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_pango_detect.nasl");
  script_require_keys("Pango/Ver");
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
include("host_details.inc");

ver = get_app_version(cpe:"cpe:/a:pango:pango", nvt:SCRIPT_OID);
if(version_is_less(version:ver, test_version:"1.24.0")){
  security_hole(0);
}
