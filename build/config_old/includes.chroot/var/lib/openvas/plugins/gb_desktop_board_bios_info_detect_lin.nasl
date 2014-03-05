###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_desktop_board_bios_info_detect_lin.nasl 14 2013-10-27 12:33:37Z jan $
#
# Desktop Boards BIOS Information Detection for Linux
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Updated Veerendra GG <veerendragg@secpod.com>
# Checking proper output in command output
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
tag_summary = "This script is detects the Desktop Boards BIOS Information
  and sets the result in KB.";

if(description)
{
  script_id(800163);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-02-11 16:37:59 +0100 (Thu, 11 Feb 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Desktop Boards BIOS Information Detection for Linux");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set Desktop Boards BIOS Information in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service.nasl","ssh_authorization.nasl");
  script_mandatory_keys("login/SSH/success");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("ssh_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

## Commands for BIOS Version and Vendor
bios_ver_cmd = "dmidecode -s bios-version";
bios_vend_cmd = "dmidecode -s bios-vendor";

## Commands for Base Board Version, Manufacturer and Product Name
base_board_ver_cmd = "dmidecode -s baseboard-version";
base_board_manu_cmd = "dmidecode -s baseboard-manufacturer";
base_board_prod_cmd = "dmidecode -s baseboard-product-name";

## Get BIOS Version and Vendor
bios_ver = ssh_cmd(socket:sock, cmd:bios_ver_cmd, timeout:120);
bios_vendor = ssh_cmd(socket:sock, cmd:bios_vend_cmd, timeout:120);

## Get Base Board Version, Manufacturer and Product Name
base_board_ver = ssh_cmd(socket:sock, cmd:base_board_ver_cmd, timeout:120);
base_board_manu = ssh_cmd(socket:sock, cmd:base_board_manu_cmd, timeout:120);
base_board_prod_name = ssh_cmd(socket:sock, cmd:base_board_prod_cmd, timeout:120);

## Set BIOS Version
if(bios_ver != NULL && !(bios_ver =~ "command not found|dmidecode:|(p|P)ermission denied"))
{
  set_kb_item(name:"DesktopBoards/BIOS/Ver", value:chomp(bios_ver));
  security_note(data:"Desktop Boards BIOS version " + bios_ver +
                     " was detected on the host");
}

## Set BIOS Vendor
if(bios_vendor != NULL && !(bios_vendor =~ "command not found|dmidecode:|(p|P)ermission denied"))
{
  set_kb_item(name:"DesktopBoards/BIOS/Vendor", value:chomp(bios_vendor));
  security_note(data:"Desktop Boards BIOS Vendor " + bios_vendor +
                     " was detected on the host");
}

## Set Base Board Version
if(base_board_ver != NULL && !(base_board_ver =~ "command not found|dmidecode:|(p|P)ermission denied"))
{
  set_kb_item(name:"DesktopBoards/BaseBoard/Ver", value:chomp(base_board_ver));
  security_note(data:"Desktop Boards Base Board version " + base_board_ver +
                     " was detected on the host");
}

## Set Base Board Manufacturer
if(base_board_manu != NULL && !(base_board_manu =~ "command not found|dmidecode:|(p|P)ermission denied"))
{
  set_kb_item(name:"DesktopBoards/BaseBoard/Manufacturer",
              value:chomp(base_board_manu));
  security_note(data:"Desktop Boards Base Board Manufacturer " +
                     base_board_manu + " was detected on the host");
}

## Set Base Board Product Name
if(base_board_prod_name != NULL && !(base_board_prod_name =~ "dmidecode:|command not found|(p|P)ermission denied"))
{
  set_kb_item(name:"DesktopBoards/BaseBoard/ProdName",
              value:chomp(base_board_prod_name));
  security_note(data:"Desktop Boards Base Board Product Name " +
                     base_board_prod_name + " was detected on the host");
}

ssh_close_connection();
