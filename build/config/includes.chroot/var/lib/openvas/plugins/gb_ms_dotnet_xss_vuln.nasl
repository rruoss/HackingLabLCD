###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_dotnet_xss_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Microsoft .NET 'ASP.NET' Cross-Site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation could allow attackers to conduct cross-site scripting
  attacks against the form control via the __VIEWSTATE parameter.";
tag_affected = "Microsoft .NET version prior to 1.1";
tag_insight = "The flaw is due to error in the default configuration of 'ASP.NET' it
  has a value of FALSE for the EnableViewStateMac property when processing the
 '__VIEWSTATE' parameter.";
tag_solution = "Upgrade to Microsoft .NET 1.1 or later,
  For updates refer to http://www.microsoft.com/downloads/details.aspx?displaylang=en";
tag_summary = "The host is running Microsoft .NET and is prone to Cross-Site
  Scripting Vulnerability.";

if(description)
{
  script_id(801345);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-06-09 08:34:53 +0200 (Wed, 09 Jun 2010)");
  script_cve_id("CVE-2010-2085");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Microsoft .NET 'ASP.NET' Cross-Site Scripting vulnerability");
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
  script_xref(name : "URL" , value : "https://www.trustwave.com/spiderlabs/advisories/TWSL2010-001.txt");
  script_xref(name : "URL" , value : "http://www.blackhat.com/presentations/bh-dc-10/Byrne_David/BlackHat-DC-2010-Byrne-SGUI-slides.pdf");

  script_description(desc);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_summary("Check the version of Microsoft .NET");
  script_category(ACT_GATHER_INFO);
  script_family("Windows");
  script_dependencies("remote-detect-MSdotNET-version.nasl");
  script_require_ports("Services/www");
  script_require_keys("dotNET/install", "aspNET/installed", "dotNet/version");
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

## Get the version from KB
dotNet = get_kb_item("dotNET/install");
if(!dotNet){
  exit(0);
}

apsdotNet = get_kb_item("aspNET/installed");
if(!aspdotNet){
  exit(0);
}

dotNet = get_kb_item("dotNet/version");
if(!dotNet){
  exit(0);
}

## Check for Microsoft .NET version less than 1.1
if(version_is_less(version:dotNet, test_version:"1.1")){
   security_warning(0);
}