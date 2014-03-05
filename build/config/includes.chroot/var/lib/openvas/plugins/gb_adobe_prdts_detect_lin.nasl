###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_detect_lin.nasl 42 2013-11-04 19:41:32Z jan $
#
# Adobe Reader Version Detection (Linux)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Updated By: Thanga Prakash S <tprakash@secpod.com> on 2013-09-04
# According to CR57 and new style script_tags.
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800108";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 42 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:41:32 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2008-10-04 09:54:24 +0200 (Sat, 04 Oct 2008)");
  script_tag(name:"detection", value:"executable version check");
  script_name("Adobe products version detection (Linux)");

  tag_summary =
"Detection of installed version of Adobe Products.

This script retrieves all Adobe Products version and saves
those in KB.";

  desc = "
  Summary:
  " + tag_summary;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }

  script_description(desc);
  script_summary("Detect the installed version of Adobe reader");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("ssh_authorization.nasl");
  script_mandatory_keys("login/SSH/success");
  exit(0);
}


include("cpe.inc");
include("host_details.inc");
include("ssh_func.inc");
include("version_func.inc");

## Variable Initialization
adobeVer = "";
adobePath = "";

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

## Get the Adobe Products installed path
adobePath = find_file(file_name:"AcroVersion", file_path:"/", useregex=TRUE,
                      regexpar:"$", sock:sock);

## Traverse over the path and try to get the version
foreach path (adobePath)
{
  path = chomp(path);
  adobeVer = get_bin_version(full_prog_name:"cat", version_argv:path,
                               ver_pattern:"[0-9.]+(_SU[0-9])?");

  if(adobeVer)
  {
    ## Set the KB
    set_kb_item(name:"Adobe/Reader/Linux/Version", value:adobeVer[0]);

    ## Build CPE
    cpe = build_cpe(value: adobeVer[0], exp:"^([0-9.]+)", base:"cpe:/a:adobe:acrobat_reader:");
    if(isnull(cpe))
      cpe = "cpe:/a:adobe:acrobat_reader";

    ## Registrer Product
    register_product(cpe:cpe, location: path, nvt:SCRIPT_OID);

    ## Build Report
    log_message(data: build_detection_report(app: "Adobe Reader",
                                             version: adobeVer[0],
                                             install: path,
                                             cpe: cpe,
                                             concluded: adobeVer[0]));
  }
}
ssh_close_connection();
