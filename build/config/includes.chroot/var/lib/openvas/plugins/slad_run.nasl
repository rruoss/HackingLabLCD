###############################################################################
# OpenVAS Vulnerability Test
#
# Fetch results of SLAD queries from a remote machine
#
# Authors:
# Dirk Jagdmann
# Michael Wiegand
#
# Copyright:
# Copyright (c) 2005 Greenbone Networks GmbH
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
################################################################################

include("revisions-lib.inc");
tag_summary = "This script connects to SLAD on a remote host to run
remote scanners.
To work properly, this script requires to be provided
with a valid SSH login by means of an SSH key with pass-
phrase if the SSH public key is passphrase-protected, or
a password to log in.";

debug = 0;

include ("ssh_func.inc");
include ("slad.inc");

if (description) {
  script_id(90002);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2007-07-31 16:52:22 +0200 (Tue, 31 Jul 2007)");
  script_name("SLAD Run");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);

  script_summary("Connects to SLAD to run programs remotely");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Greenbone Networks GmbH");
  script_family("General");

  script_dependencies ("find_service.nasl", "ssh_authorization.nasl");
  script_require_ports (22, "Services/ssh");

  # Dynamic entries for running from slad.inc
  if(defined_func("init_add_preferences")) {
    init_add_preferences ();
  }

  script_mandatory_keys("login/SSH/success");

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

{
  if (debug)
    dump_preferences ();

  sock = ssh_login_or_reuse_connection();
  if(!sock) {
    exit(0);
  }
  run_slad (sock: sock, slad_exe: "/opt/slad/bin/sladd");

  close (sock);
}
