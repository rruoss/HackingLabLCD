###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_serendipity_file_upload_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Serendipity File Extension Processing Arbitrary File Upload Vulnerability
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
tag_impact = "Successful exploitation will allow attacker to upload PHP scripts and execute
  arbitrary commands on a web server with a specific configuration.
  Impact Level: Application";
tag_affected = "Serendipity version prior to 1.5 on all platforms.";
tag_insight = "The flaw is due to an input validation error in the file upload functionality
  when processing a file with a filename containing multiple file extensions.";
tag_solution = "Upgrade to Serendipity version 1.5 or later.
  For updates refer to http://www.s9y.org/12.html";
tag_summary = "This host is running Serendipity and is prone to arbitrary file upload
  vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.901091";
CPE = "cpe:/a:s9y:serendipity";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-01-04 15:26:56 +0100 (Mon, 04 Jan 2010)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-4412");
  script_name("Serendipity File Extension Processing Arbitrary File Upload Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37830");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/54985");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/3626");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2009/12/21/1");

  script_description(desc);
  script_summary("Check for the version of Serendipity");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("serendipity_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("Serendipity/installed");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

serPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!serPort){
  exit(0);
}

if(!ver = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:serPort))exit(0);

if(ver != NULL)
{
  # Check for Serendipity version < 1.5
  if(version_is_less(version:ver, test_version:"1.5")){
    security_hole(serPort);
  }
}
