# OpenVAS Vulnerability Test
# $Id: smbcl_flash_player_CB-A08-0059.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Adobe Flash Player 9.0.115.0 and earlier vulnerability (Win)
#
# Authors:
# Carsten Koch-Mauthe <c.koch-mauthe at dn-systems.de>
# Modified to Implement based on 'smb_nt.inc'
#  - By Sharath S <sharaths@secpod.com> On 2009-09-14
#
# Copyright:
# Copyright (C) 2008 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_impact = "- CVE 2007-5275
    The Adobe Macromedia Flash 9 plug-in allows remote attackers to cause a
    victim machine to establish TCP sessions with arbitrary hosts via a Flash
    (SWF) movie, related to lack of pinning of a hostname to a single IP address
    after receiving an allow-access-from element in a cross-domain-policy XML
    document, and the availability of a Flash Socket class that does not use
    the browser's DNS pins, aka DNS rebinding attacks, a different issue than
    CVE-2002-1467 and CVE-2007-4324.
  - CVE 2007-6019
    Adobe Flash Player 9.0.115.0 and earlier, and 8.0.39.0 and earlier, allows
    remote attackers to execute arbitrary code via an SWF file with a modified
    DeclareFunction2 Actionscript tag, which prevents an object from being
    instantiated properly.
  - CVE 2007-6243
    Adobe Flash Player 9.x up to 9.0.48.0, 8.x up to 8.0.35.0, and 7.x up to
    7.0.70.0 does not sufficiently restrict the interpretation and usage of
    cross-domain policy files, which makes it easier for remote attackers to
    conduct cross-domain and cross-site scripting (XSS) attacks.
  - CVE 2007-6637
    Multiple cross-site scripting (XSS) vulnerabilities in Adobe Flash Player
    allow remote attackers to inject arbitrary web script or HTML via a crafted
    SWF file, related to 'pre-generated SWF files' and Adobe Dreamweaver CS3 or
    Adobe Acrobat Connect. NOTE: the asfunction: vector is already covered by
    CVE-2007-6244.1.
  - CVE 2008-1654
    Interaction error between Adobe Flash and multiple Universal Plug and Play
    (UPnP) services allow remote attackers to perform Cross-Site Request Forgery
    (CSRF) style attacks by using the Flash navigateToURL function to send a SOAP
    message to a UPnP control point, as demonstrated by changing the primary DNS
    server.
  - CVE 2008-1655
    Unspecified vulnerability in Adobe Flash Player 9.0.115.0 and earlier, and
    8.0.39.0 and earlier, makes it easier for remote attackers to conduct DNS
    rebinding attacks via unknown vectors.";

tag_summary = "The remote host is probably affected by the vulnerabilities described in
  CVE-2007-5275, CVE-2007-6019, CVE-2007-6243, CVE-2007-6637, CVE-2008-1654,
  CVE-2008-1655.";

tag_solution = "All Adobe Flash Player users should upgrade to the latest version:
  http://get.adobe.com/flashplayer/";

# $Revision: 16 $

  desc = "
  Summary:
  " + tag_summary + "
  Impact:
  " + tag_impact + "
  Solution:
  " + tag_solution;
if(description)
{
  script_xref(name : "URL" , value : "http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5275");
  script_xref(name : "URL" , value : "http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6019");
  script_xref(name : "URL" , value : "http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6243");
  script_xref(name : "URL" , value : "http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6637");
  script_xref(name : "URL" , value : "http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1654");
  script_xref(name : "URL" , value : "http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1655");
  script_id(90019);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-09-03 22:30:27 +0200 (Wed, 03 Sep 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2007-5275", "CVE-2007-6019", "CVE-2007-6243",
                "CVE-2007-6637", "CVE-2008-1654", "CVE-2008-1655");
  script_bugtraq_id(26930, 28694, 26966, 27034, 28696, 28697);
  script_name("Adobe Flash Player 9.0.115.0 and earlier vulnerability (Win)");

  script_description(desc);
  script_summary("Determine the version of Flashplayer");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
  }
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

filePath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(!filePath){
  exit(0);
}

flashPath = filePath + "\Macromed\Flash\";
foreach filespec (make_list("NPSWF32.dll", "Flash.ocx", "Flash6.ocx"))
{
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:filePath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                      string:flashPath + filespec);
  fileVer = GetVer(file:file, share:share);
  if(fileVer)
  {
    if(version_is_less_equal(version:fileVer, test_version:"9.0.115.0"))
    {
      desc = desc + '\n\nVulnerable: Version < 9.0.115.0\nDetected: ' + fileVer + ' at ' + share + file;
      security_hole(0);
      exit(0);
    }
  }
}
