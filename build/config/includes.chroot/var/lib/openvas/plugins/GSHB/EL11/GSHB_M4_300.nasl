###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_300.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 11. EL, Maﬂnahme 4.300
#
# Authors:
# Thomas Rotter <T.Rotter@dn-systems.de>
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
tag_summary = "IT-Grundschutz M4.300: Informationsschutz bei Druckern, Kopierern und Multifunktionsger‰ten

  Diese Pr¸fung bezieht sich auf die 11. Erg‰nzungslieferung (11. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Maﬂnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Erg‰nzungslieferung bezieht. Titel und Inhalt kˆnnen sich bei einer
  Aktualisierung ‰ndern, allerdings nicht die Kernthematik.

  http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04300.html";

if(description)
{
  script_id(894300);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Thu Feb 25 12:13:41 2010 +0100");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.300: Informationsschutz bei Druckern, Kopierern und Multifunktionsger‰ten");
  
  if (! OPENVAS_VERSION)
  {
    desc = "Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!";
    script_description(desc);
    script_summary("IT-Grundschutz M4.300: Informationsschutz bei Druckern, Kopierern und Multifunktionsger‰ten");
    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
    script_family("IT-Grundschutz-11");
    exit(0);
  }
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("IT-Grundschutz M4.300: Informationsschutz bei Druckern, Kopierern und Multifunktionsger‰ten");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-11");
  script_mandatory_keys("Compliance/Launch/GSHB-11");
  script_dependencies("GSHB/GSHB_Printer_SSL-TLS.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.300: Informationsschutz bei Druckern, Kopierern und Multifunktionsger‰ten\n';



if (! OPENVAS_VERSION)
  {
        set_kb_item(name:"GSHB-11/M4_300/result", value:"nicht zutreffend");
        set_kb_item(name:"GSHB-11/M4_300/desc", value:"Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!");
        set_kb_item(name:"GSHB-11/M4_300/name", value:name);
    log_message(port:0, proto: "IT-Grundschutz", data:string("Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!"));  
    exit(0);
}

gshbm =  "IT-Grundschutz M4.300: ";

Printer = get_kb_item("GSHB/Printer");
IPPCert = get_kb_item("GSHB/IPP-Cert");

if(Printer >< "False"){
  result = string("nicht zutreffend");
  desc = string("Das Zielsystem ist kein Drucker oder IPP-Printserver\nund kann nicht getestet werden");
}else if(Printer >< "True"){
  result = string("nicht erf¸llt");
  desc = string('Das Zielsystem ist ein Drucker ohne IPP, so das\nTLS/SSL nicht konfiguriert werden kann. Sie sollten\neinen IPP-Printserver aufsetzen.');
}else if(Printer >< "IPP"){
    if (IPPCert == "none"){
      result = string("nicht erf¸llt");
      desc = string('Das Zielsystem ist ein Drucker oder Printserver mit\nIPP. Anscheindend wurde TLS/SSL nicht konfiguriert,\nso dasss keine verschl¸sselte Daten¸bertragung statt-\nfinden konnte. Sie sollten TLS/SSL aktivieren.');

    }else if(cert >!< "error"){
      result = string("erf¸llt");
      desc = string('Das Zielsystem ist ein Drucker oder Printserver mit\nIPP. Folgende TLS/SSL-Zertifikatsdaten sind\nhinterlegt:\n' + IPPCert);
    }else{
      result = string("Fehler");
      desc = string('Beim Auslesen des TLS/SSL-Zertifikates trat ein\nFehler auf.');

    }
}


set_kb_item(name:"GSHB-11/M4_300/result", value:result);
set_kb_item(name:"GSHB-11/M4_300/desc", value:desc);
set_kb_item(name:"GSHB-11/M4_300/name", value:name);

silence = get_kb_item("GSHB-11/silence");

if (silence){
exit(0);
} else {
  report = 'Ergebnisse zum IT-Grundschutz, 11. Erg‰nzungslieferung:\n\n';
  report = report + name + 'Ergebnis:\t' + result +
           '\nDetails:\t' + desc + '\n\n';
    if ("nicht erf¸llt" >< result || result >< "Fehler"){
    security_hole(port:0, proto: "IT-Grundschutz", data:report);
    } else if (result >< "unvollst‰ndig"){
    security_warning(port:0, proto: "IT-Grundschutz", data:report);
    } else if (result >< "erf¸llt" || result >< "nicht zutreffend"){
    security_note(port:0, proto: "IT-Grundschutz", data:report);
    }
exit(0);
}

