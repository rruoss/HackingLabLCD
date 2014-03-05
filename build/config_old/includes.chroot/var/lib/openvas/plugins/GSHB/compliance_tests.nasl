###############################################################################
# OpenVAS Vulnerability Test
# $Id: compliance_tests.nasl 9 2013-10-27 09:38:41Z jan $
#
# Compliance Tests
#
# Authors:
# Michael Wiegand <michael.wiegand@intevation.de>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "This script controls various compliance tests like IT-Grundschutz.";

if(description)
{
  script_id(95888);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Compliance Tests");
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("Compliance Tests");
  script_category(ACT_SETTINGS);
  script_copyright("Copyright (c) 2009-2011 Greenbone Networks GmbH");
  script_family("Compliance");

  script_add_preference(name:"Launch IT-Grundschutz (10. EL)", type:"checkbox", value:"no");
  script_add_preference(name:"Launch IT-Grundschutz (11. EL)", type:"checkbox", value:"no");
  script_add_preference(name:"Launch IT-Grundschutz (12. EL)", type:"checkbox", value:"no");
  script_add_preference(name:"Verbose IT-Grundschutz results", type:"checkbox", value:"no");
  script_add_preference(name:"Testuser Common Name", type:"entry", value:"CN");
  script_add_preference(name:"Testuser Organization Unit", type:"entry", value:"OU");
  script_add_preference(name:"Windows Domaenenfunktionsmodus", type:"radio", value:"Unbekannt;Windows 2000 gemischt und Windows 2000 pur;Windows Server 2003 Interim;Windows Server 2003;Windows Server 2008;Windows Server 2008 R2");

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

# Set KB item if IT-Grundschutz is enabled
launch_gshb_10 = script_get_preference("Launch IT-Grundschutz (10. EL)");
if (launch_gshb_10 == "yes") {
  set_kb_item(name: "Compliance/Launch/GSHB-10", value: TRUE);
  set_kb_item(name: "Compliance/Launch/GSHB", value: TRUE);
}
launch_gshb_11 = script_get_preference("Launch IT-Grundschutz (11. EL)");
if (launch_gshb_11 == "yes") {
  set_kb_item(name: "Compliance/Launch/GSHB-11", value: TRUE);
  set_kb_item(name: "Compliance/Launch/GSHB", value: TRUE);
}
launch_gshb_12 = script_get_preference("Launch IT-Grundschutz (12. EL)");
if (launch_gshb_12 == "yes") {
  set_kb_item(name: "Compliance/Launch/GSHB-12", value: TRUE);
  set_kb_item(name: "Compliance/Launch/GSHB", value: TRUE);
}

# Set KB item if IT-Grundschutz silence is requested
verbose_gshb = script_get_preference("Verbose IT-Grundschutz results");
if (verbose_gshb == "no") {
  set_kb_item(name: "GSHB-10/silence", value: "Wahr");
  set_kb_item(name: "GSHB-11/silence", value: "Wahr");
  set_kb_item(name: "GSHB-12/silence", value: "Wahr");
}
CN = script_get_preference("Testuser Common Name");
OU = script_get_preference("Testuser Organization Unit");
DomFunkMod = script_get_preference("Windows Domaenenfunktionsmodus");

if (DomFunkMod == "Unbekannt")DomFunk = "none";
else if (DomFunkMod == "Windows 2000 gemischt und Windows 2000 pur")DomFunk = "0";
else if (DomFunkMod == "Windows Server 2003 Interim")DomFunk = "1";
else if (DomFunkMod == "Windows Server 2003")DomFunk = "2";
else if (DomFunkMod == "Windows Server 2008")DomFunk = "3";
else if (DomFunkMod == "Windows Server 2008 R2")DomFunk = "4";
else if (!DomFunk)DomFunk = "none";

set_kb_item(name:"GSHB/CN", value:CN);
set_kb_item(name:"GSHB/OU", value:OU);
set_kb_item(name:"GSHB/DomFunkMod", value:DomFunk);

exit(0);


