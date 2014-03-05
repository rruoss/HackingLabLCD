###############################################################################
# OpenVAS Vulnerability Test
# $Id:
#
# Check if an TFTP Server is running and was start with -s Option
#
# Authors:
# Thomas Rotter <T.Rotter@dn-systems.de>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
#
#
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
tag_summary = "Check if an TFTP Server is running and was start with -s Option";

if(description)
{
  script_id(96101);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Wed May 05 15:06:40 2010 +0200");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Check if an TFTP Server is running and was start with -s Option");

  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("Check if an TFTP Server is running and was start with -s Option");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_dependencies("tftpd_detect.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("tftp.inc");

port = get_kb_item('Services/udp/tftp');
if (! port) port = 69;

if ( tftp_alive(port: port) ) {
  get = tftp_get(port:port, path:"//etc//passwd");
  if (!get) tftp = "ok";
  else tftp = "fail";
}
else tftp = "none";

set_kb_item(name: "GSHB/TFTP/s-option", value:tftp);

exit(0);
