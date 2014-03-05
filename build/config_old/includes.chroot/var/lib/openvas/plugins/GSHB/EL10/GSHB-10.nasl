##############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB-10.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 10. Ergänzungslieferung
#
# Authors:
# Thomas Rotter <T.Rotter@dn-systems.de>
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
tag_summary = "Zusammenfassung von Tests gemäß IT-Grundschutz
  (in 10. Ergänzungslieferung).

  Diese Routinen prüfen sämtliche Maßnahmen des
  IT-Grundschutz des Bundesamts für Sicherheit
  in der Informationstechnik (BSI) auf den
  Zielsystemen soweit die Maßnahmen auf automatisierte
  Weise abgeprüft werden können.";
massnahmen = make_list("M4_001", "M4_002", "M4_003", "M4_004", "M4_005",
 "M4_006", "M4_007", "M4_008", "M4_009", "M4_010", "M4_011", "M4_012", "M4_013",
 "M4_014", "M4_015", "M4_016", "M4_017", "M4_018", "M4_019", "M4_020", "M4_021",
 "M4_022", "M4_023", "M4_024", "M4_025", "M4_026", "M4_027", "M4_028", "M4_029",
 "M4_030", "M4_031", "M4_032", "M4_033", "M4_034", "M4_035", "M4_036", "M4_037",
 "M4_038", "M4_039", "M4_040", "M4_041", "M4_042", "M4_043", "M4_044", "M4_045",
 "M4_046", "M4_047", "M4_048", "M4_049", "M4_050", "M4_051", "M4_052", "M4_053",
 "M4_054", "M4_055", "M4_056", "M4_057", "M4_058", "M4_059", "M4_060", "M4_061",
 "M4_062", "M4_063", "M4_064", "M4_065", "M4_066", "M4_067", "M4_068", "M4_069",
 "M4_070", "M4_071", "M4_072", "M4_073", "M4_074", "M4_075", "M4_076", "M4_077",
 "M4_078", "M4_079", "M4_080", "M4_081", "M4_082", "M4_083", "M4_084", "M4_085",
 "M4_086", "M4_087", "M4_088", "M4_089", "M4_090", "M4_091", "M4_092", "M4_093",
 "M4_094", "M4_095", "M4_096", "M4_097", "M4_098", "M4_099", "M4_100", "M4_101",
 "M4_102", "M4_103", "M4_104", "M4_105", "M4_106", "M4_107", "M4_108", "M4_109",
 "M4_110", "M4_111", "M4_112", "M4_113", "M4_114", "M4_115", "M4_116", "M4_117",
 "M4_118", "M4_119", "M4_120", "M4_121", "M4_122", "M4_123", "M4_124", "M4_125",
 "M4_126", "M4_127", "M4_128", "M4_129", "M4_130", "M4_131", "M4_132", "M4_133",
 "M4_134", "M4_135", "M4_136", "M4_137", "M4_138", "M4_139", "M4_140", "M4_141",
 "M4_142", "M4_143", "M4_144", "M4_145", "M4_146", "M4_147", "M4_148", "M4_149",
 "M4_150", "M4_151", "M4_152", "M4_153", "M4_154", "M4_155", "M4_156", "M4_157",
 "M4_158", "M4_159", "M4_160", "M4_161", "M4_162", "M4_163", "M4_164", "M4_165",
 "M4_166", "M4_167", "M4_168", "M4_169", "M4_170", "M4_171", "M4_172", "M4_173",
 "M4_174", "M4_175", "M4_176", "M4_177", "M4_178", "M4_179", "M4_180", "M4_181",
 "M4_182", "M4_183", "M4_184", "M4_185", "M4_186", "M4_187", "M4_188", "M4_189",
 "M4_190", "M4_191", "M4_192", "M4_193", "M4_194", "M4_195", "M4_196", "M4_197",
 "M4_198", "M4_199", "M4_200", "M4_201", "M4_202", "M4_203", "M4_204", "M4_205",
 "M4_206", "M4_207", "M4_208", "M4_209", "M4_210", "M4_211", "M4_212", "M4_213",
 "M4_214", "M4_215", "M4_216", "M4_217", "M4_218", "M4_219", "M4_220", "M4_221",
 "M4_222", "M4_223", "M4_224", "M4_225", "M4_226", "M4_227", "M4_228", "M4_229",
 "M4_230", "M4_231", "M4_232", "M4_233", "M4_234", "M4_235", "M4_236", "M4_237",
 "M4_238", "M4_239", "M4_240", "M4_241", "M4_242", "M4_243", "M4_244", "M4_245",
 "M4_246", "M4_247", "M4_248", "M4_249", "M4_250", "M4_251", "M4_252", "M4_253",
 "M4_254", "M4_255", "M4_256", "M4_257", "M4_258", "M4_259", "M4_260", "M4_261",
 "M4_262", "M4_263", "M4_264", "M4_265", "M4_266", "M4_267", "M4_268", "M4_269",
 "M4_270", "M4_271", "M4_272", "M4_273", "M4_274", "M4_275", "M4_276", "M4_277",
 "M4_278", "M4_279", "M4_280", "M4_281", "M4_282", "M4_283", "M4_284", "M4_285",
 "M4_286", "M4_287", "M4_288", "M4_289", "M4_290", "M4_291", "M4_292", "M4_293",
 "M4_294", "M4_295", "M4_296", "M4_297", "M4_298", "M4_299", "M4_300", "M4_301",
 "M4_302", "M4_303", "M4_304", "M4_305", "M4_306", "M4_307", "M4_308", "M4_309",
 "M4_310", "M4_311", "M4_312", "M4_313", "M4_314", "M4_315", "M4_316", "M4_317",
 "M4_318", "M4_319", "M4_320", "M4_321", "M4_322", "M4_323", "M4_324", "M5_001",
 "M5_002", "M5_003", "M5_004", "M5_005", "M5_006", "M5_007", "M5_008",
 "M5_009", "M5_010", "M5_011", "M5_012", "M5_013", "M5_014", "M5_015", "M5_016",
 "M5_017", "M5_018", "M5_019", "M5_020", "M5_021", "M5_022", "M5_023", "M5_024",
 "M5_025", "M5_026", "M5_027", "M5_028", "M5_029", "M5_030", "M5_031", "M5_032",
 "M5_033", "M5_034", "M5_035", "M5_036", "M5_037", "M5_038", "M5_039", "M5_040",
 "M5_041", "M5_042", "M5_043", "M5_044", "M5_045", "M5_046", "M5_047", "M5_048",
 "M5_049", "M5_050", "M5_051", "M5_052", "M5_053", "M5_054", "M5_055",
 "M5_056", "M5_057", "M5_058", "M5_059", "M5_060", "M5_061", "M5_062",
 "M5_063", "M5_064", "M5_065", "M5_066", "M5_067", "M5_068", "M5_069", "M5_070",
 "M5_071", "M5_072", "M5_073", "M5_074", "M5_075", "M5_076", "M5_077", "M5_078",
 "M5_079", "M5_080", "M5_081", "M5_082", "M5_083", "M5_084", "M5_085", "M5_086",
 "M5_087", "M5_088", "M5_089", "M5_090", "M5_091", "M5_091", "M5_092", "M5_093",
 "M5_094", "M5_095", "M5_096", "M5_097", "M5_098", "M5_099", "M5_100", "M5_101",
 "M5_102", "M5_103", "M5_104", "M5_105", "M5_106", "M5_107", "M5_108", "M5_109",
 "M5_110", "M5_111", "M5_112", "M5_113", "M5_114", "M5_115", "M5_116", "M5_117",
 "M5_118", "M5_119", "M5_120", "M5_121", "M5_122", "M5_123", "M5_124", "M5_125",
 "M5_126", "M5_127", "M5_128", "M5_129", "M5_130", "M5_131", "M5_132", "M5_133",
 "M5_134", "M5_135", "M5_136", "M5_137", "M5_138", "M5_139", "M5_140", "M5_141",
 "M5_142", "M5_143", "M5_144", "M5_145", "M5_146", "M5_147", "M5_148", "M5_149",
 "M5_150");

depend = make_list("M4_001", "M4_002", "M4_003", "M4_004", "M4_005", "M4_007",
 "M4_009", "M4_014", "M4_015", "M4_016", "M4_017", "M4_018",
 "M4_019", "M4_020", "M4_021", "M4_022", "M4_023", "M4_026", "M4_033",
 "M4_036", "M4_037", "M4_040", "M4_048", "M4_049", "M4_052",
 "M4_055", "M4_057", "M4_077", "M4_080", "M4_093",
 "M4_094", "M4_096", "M4_097", "M4_098", "M4_106", "M4_135", "M4_146",
 "M4_147", "M4_178", "M4_179", "M4_186", "M4_189", "M4_190",
 "M4_192", "M4_195", "M4_196", "M4_197", "M4_200",
 "M4_227", "M4_238", "M4_244", "M4_249", "M4_277",
 "M4_284", "M4_285", "M4_287", "M4_288", "M4_300", "M4_305", "M4_310", "M4_313",
 "M4_315", "M5_008", "M5_009", "M5_017", "M5_018", "M5_019", "M5_020",
 "M5_021", "M5_034", "M5_037", "M5_053", "M5_055",
 "M5_059", "M5_063", "M5_064", "M5_066", "M5_072", "M5_090",
 "M5_091", "M5_101", "M5_102", "M5_103", "M5_104", "M5_105",
 "M5_107", "M5_109", "M5_123", "M5_131",
 "M5_145", "M5_147");



if(description)
{
  script_id(95000);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Thu Jan 14 14:29:35 2010 +0100");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz, 10. EL");
  if (! OPENVAS_VERSION)
        {
    desc = "
    Leider setzen Sie einen zu alten OpenVAS Scan-Server ein.
    Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!";
    script_description(desc);
    script_summary("Grundschutzhandbuch");
    script_category(ACT_END);
    script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
    script_family("Compliance");
    exit(0);
        }
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("Grundschutzhandbuch");
  script_category(ACT_END);
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("Compliance");
  script_mandatory_keys("Compliance/Launch/GSHB-10");
  script_add_preference(name:"Berichtformat", type:"radio", value:"Text;Tabellarisch;Text und Tabellarisch");
  script_require_keys("GSHB-10/silence");
  script_dependencies("GSHB/compliance_tests.nasl");
  foreach d (depend) script_dependencies("GSHB/EL10/GSHB_" + d + ".nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

if (! OPENVAS_VERSION)
{
  log_message(port:0, proto: "IT-Grundschutz", data:"Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!");
  log_message(port:0, proto: "IT-Grundschutz-T", data:"Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!");
  exit(0);
}

mtitel = "
M4.001 Passwortschutz für IT-Systeme
M4.002 Bildschirmsperre
M4.003 Regelmäßiger Einsatz eines Anti-Viren-Programms
M4.004 Geeigneter Umgang mit Laufwerken für Wechselmedien und externen Datenspeichern
M4.005 Protokollierung der TK-Administrationsarbeiten
M4.006 Revision der TK-Anlagenkonfiguration
M4.007 Änderung voreingestellter Passwörter
M4.008 Schutz des TK-Bedienplatzes
M4.009 Einsatz der Sicherheitsmechanismen von XWindow
M4.010 Passwortschutz für TK-Endgeräte
M4.011 Absicherung der TK-Anlagen-Schnittstellen
M4.012 Sperren nicht benötigter TK-Leistungsmerkmale
M4.013 Sorgfältige Vergabe von IDs
M4.014 Obligatorischer Passwortschutz unter Unix
M4.015 Gesichertes Login
M4.016 Zugangsbeschränkungen für Accounts und oder Terminals
M4.017 Sperren und Löschen nicht benötigter Accounts und Terminals
M4.018 Administrative und technische Absicherung des Zugangs zum Monitor- und Single-User-Modus
M4.019 Restriktive Attributvergabe bei Unix-Systemdateien und -verzeichnissen
M4.020 Restriktive Attributvergabe bei Unix-Benutzerdateien und -verzeichnissen
M4.021 Verhinderung des unautorisierten Erlangens von Administratorrechten
M4.022 Verhinderung des Vertraulichkeitsverlusts schutzbedürftiger Daten im Unix-System
M4.023 Sicherer Aufruf ausführbarer Dateien
M4.024 Sicherstellung einer konsistenten Systemverwaltung
M4.025 Einsatz der Protokollierung im Unix-System
M4.026 Regelmäßiger Sicherheitscheck des Unix-Systems
M4.027 Zugriffsschutz am Laptop
M4.028 Software-Reinstallation bei Benutzerwechsel eines Laptops
M4.029 Einsatz eines Verschlüsselungsproduktes für tragbare IT-Systeme
M4.030 Nutzung der in Anwendungsprogrammen angebotenen Sicherheitsfunktionen
M4.031 Sicherstellung der Energieversorgung im mobilen Einsatz
M4.032 Physikalisches Löschen der Datenträger vor und nach Verwendung
M4.033 Einsatz eines Viren-Suchprogramms bei Datenträgeraustausch und Datenübertragung
M4.034 Einsatz von Verschlüsselung, Checksummen oder Digitalen Signaturen
M4.035 Verifizieren der zu übertragenden Daten vor Versand
M4.036 Sperren bestimmter Faxempfänger- Rufnummern
M4.037 Sperren bestimmter Absender-Faxnummern
M4.038 Abschalten nicht benötigter Leistungsmerkmale
M4.039 Abschalten des Anrufbeantworters bei Anwesenheit
M4.040 Verhinderung der unautorisierten Nutzung des Rechnermikrofons
M4.041 Einsatz angemessener Sicherheitsprodukte für IT-Systeme
M4.042 Implementierung von Sicherheitsfunktionalitäten in der IT-Anwendung
M4.043 Faxgerät mit automatischer Eingangskuvertierung
M4.044 Diese Maßnahme ist entfallen!
M4.045 Einrichtung einer sicheren Peer-to-Peer-Umgebung unter WfW
M4.046 Nutzung des Anmeldepasswortes unter WfW und Windows 95
M4.047 Protokollierung der Sicherheitsgateway-Aktivitäten
M4.048 Passwortschutz unter NT-basierten Windows-Systemen
M4.049 Absicherung des Boot-Vorgangs für ein Windows NT/2000/XP System
M4.050 Strukturierte Systemverwaltung unter Windows NT
M4.051 Benutzerprofile zur Einschränkung der Nutzungsmöglichkeiten von Windows NT
M4.052 Geräteschutz unter NT-basierten Windows-Systemen
M4.053 Restriktive Vergabe von Zugriffsrechten auf Dateien und Verzeichnisse unter Windows NT
M4.054 Protokollierung unter Windows NT
M4.055 Sichere Installation von Windows NT
M4.056 Sicheres Löschen unter Windows-Betriebssystemen
M4.057 Deaktivieren der automatischen CD-ROM Erkennung
M4.058 Freigabe von Verzeichnissen unter Windows 95
M4.059 Deaktivieren nicht benötigter ISDN-Karten-Funktionalitäten
M4.060 Deaktivieren nicht benötigter ISDN-Router-Funktionalitäten
M4.061 Nutzung vorhandener Sicherheitsmechanismen der ISDN-Komponenten
M4.062 Einsatz eines D-Kanal-Filters
M4.063 Sicherheitstechnische Anforderungen an den Telearbeitsrechner
M4.064 Verifizieren der zu übertragenden Daten vor Weitergabe / Beseitigung von Restinformationen
M4.065 Test neuer Hard- und Software
M4.066 Diese Maßnahme ist entfallen!
M4.067 Sperren und Löschen nicht benötigter Datenbank-Accounts
M4.068 Sicherstellung einer konsistenten Datenbankverwaltung
M4.069 Regelmäßiger Sicherheitscheck der Datenbank
M4.070 Durchführung einer Datenbanküberwachung
M4.071 Restriktive Handhabung von Datenbank-Links
M4.072 Datenbank-Verschlüsselung
M4.073 Festlegung von Obergrenzen für selektierbare Datensätze
M4.074 Diese Maßnahme ist entfallen!
M4.075 Schutz der Registrierung unter Windows NT/2000/XP
M4.076 Sichere Systemversion von Windows NT
M4.077 Schutz der Administratorkonten unter Windows NT
M4.078 Sorgfältige Durchführung von Konfigurationsänderungen
M4.079 Sichere Zugriffsmechanismen bei lokaler Administration
M4.080 Sichere Zugriffsmechanismen bei Fernadministration
M4.081 Audit und Protokollierung der Aktivitäten im Netz
M4.082 Sichere Konfiguration der aktiven Netzkomponenten
M4.083 Update/Upgrade von Soft- und Hardware im Netzbereich
M4.084 Nutzung der BIOS-Sicherheitsmechanismen
M4.085 Geeignetes Schnittstellendesign bei Kryptomodulen
M4.086 Sichere Rollenteilung und Konfiguration der Kryptomodule
M4.087 Physikalische Sicherheit von Kryptomodulen
M4.088 Anforderungen an die Betriebssystem-Sicherheit beim Einsatz von Kryptomodulen
M4.089 Abstrahlsicherheit
M4.090 Einsatz von kryptographischen Verfahren auf den verschiedenen Schichten des ISO/OSIReferenzmodells
M4.091 Sichere Installation eines Systemmanagementsystems
M4.092 Sicherer Betrieb eines Systemmanagementsystems
M4.093 Regelmäßige Integritätsprüfung
M4.094 Schutz der WWW-Dateien
M4.095 Minimales Betriebssystem
M4.096 Abschaltung von DNS
M4.097 Ein Dienst pro Server
M4.098 Kommunikation durch Paketfilter auf Minimum beschränken
M4.099 Schutz gegen nachträgliche Veränderungen von Informationen
M4.100 Sicherheitsgateways und aktive Inhalte
M4.101 Sicherheitsgateways und Verschlüsselung
M4.102 C2-Sicherheit unter Novell 4.11
M4.103 DHCP-Server unter Novell Netware 4.x
M4.104 LDAP Services for NDS
M4.105 Erste Maßnahmen nach einer UnixStandardinstallation
M4.106 Aktivieren der Systemprotokollierung
M4.107 Nutzung von Hersteller-Ressourcen
M4.108 Vereinfachtes und sicheres Netzmanagement mit DNS Services unter Novell NetWare 4.11
M4.109 Software-Reinstallation bei Arbeitsplatzrechnern
M4.110 Diese Maßnahme ist entfallen!
M4.111 Diese Maßnahme ist entfallen!
M4.112 Diese Maßnahme ist entfallen!
M4.113 Nutzung eines Authentisierungsservers bei Remote-Access-VPNs
M4.114 Nutzung der Sicherheitsmechanismen von Mobiltelefonen
M4.115 Sicherstellung der Energieversorgung von Mobiltelefonen
M4.116 Sichere Installation von Lotus Notes
M4.117 Sichere Konfiguration eines Lotus Notes Servers
M4.118 Konfiguration als Lotus Notes Server
M4.119 Einrichten von Zugangsbeschränkungen auf Lotus Notes Server
M4.120 Konfiguration von Zugriffslisten auf Lotus Notes Datenbanken
M4.121 Konfiguration der Zugriffsrechte auf das Namens- und Adressbuch von Lotus Notes
M4.122 Konfiguration für den Browser-Zugriff auf Lotus Notes
M4.123 Einrichten des SSL-geschützten Browser-Zugriffs auf Lotus Notes
M4.124 Konfiguration der Authentisierungsmechanismen beim Browser-Zugriff auf Lotus Notes
M4.125 Einrichten von Zugriffsbeschränkungen beim Browser-Zugriff auf Lotus Notes Datenbanken
M4.126 Sichere Konfiguration eines Lotus Notes Clients
M4.127 Sichere Browser-Konfiguration für den Zugriff auf Lotus Notes
M4.128 Sicherer Betrieb von Lotus Notes
M4.129 Sicherer Umgang mit Notes-ID-Dateien
M4.130 Sicherheitsmaßnahmen nach dem Anlegen neuer Lotus Notes Datenbanken
M4.131 Verschlüsselung von Lotus Notes Datenbanken
M4.132 Überwachen eines Lotus Notes-Systems
M4.133 Geeignete Auswahl von Authentikationsmechanismen
M4.134 Wahl geeigneter Datenformate
M4.135 Restriktive Vergabe von Zugriffsrechten auf Systemdateien
M4.136 Sichere Installation von Windows 2000
M4.137 Sichere Konfiguration von Windows 2000
M4.138 Konfiguration von Windows Server als Domänen-Controller
M4.139 Konfiguration von Windows 2000 als Server
M4.140 Sichere Konfiguration wichtiger Windows 2000 Dienste
M4.141 Sichere Konfiguration des DDNS unter Windows 2000
M4.142 Sichere Konfiguration des WINS unter Windows 2000
M4.143 Sichere Konfiguration des DHCP unter Windows 2000
M4.144 Nutzung der Windows 2000 CA
M4.145 Sichere Konfiguration von RRAS unter Windows 2000
M4.146 Sicherer Betrieb von Windows 2000/XP
M4.147 Sichere Nutzung von EFS unter Windows 2000/XP
M4.148 Überwachung eines Windows 2000/XP Systems
M4.149 Datei- und Freigabeberechtigungen unter Windows 2000/XP
M4.150 Konfiguration von Windows 2000 als Workstation
M4.151 Sichere Installation von Internet-PCs
M4.152 Sicherer Betrieb von Internet-PCs
M4.153 Sichere Installation von Novell eDirectory
M4.154 Sichere Installation der Novell eDirectory Clientsoftware
M4.155 Sichere Konfiguration von Novell eDirectory
M4.156 Sichere Konfiguration der Novell eDirectory Clientsoftware
M4.157 Einrichten von Zugriffsberechtigungen auf Novell eDirectory
M4.158 Einrichten des LDAP-Zugriffs auf Novell eDirectory
M4.159 Sicherer Betrieb von Novell eDirectory
M4.160 Überwachen von Novell eDirectory
M4.161 Sichere Installation von Exchange/Outlook 2000
M4.162 Sichere Konfiguration von Exchange 2000 Servern
M4.163 Zugriffsrechte auf Exchange 2000 Objekte
M4.164 Browser-Zugriff auf Exchange 2000
M4.165 Sichere Konfiguration von Outlook 2000
M4.166 Sicherer Betrieb von Exchange/Outlook 2000
M4.167 Überwachung und Protokollierung von Exchange 2000 Systemen
M4.168 Auswahl eines geeigneten Archivsystems
M4.169 Verwendung geeigneter Archivmedien
M4.170 Auswahl geeigneter Datenformate für die Archivierung von Dokumenten
M4.171 Schutz der Integrität der Index-Datenbank von Archivsystemen
M4.172 Protokollierung der Archivzugriffe
M4.173 Regelmäßige Funktions- und Recoverytests bei der Archivierung
M4.174 Vorbereitung der Installation von Windows NT/2000 für den IIS
M4.175 Sichere Konfiguration von Windows NT/2000 für den IIS
M4.176 Auswahl einer Authentisierungsmethode für Webangebote
M4.177 Sicherstellung der Integrität und Authentizität von Softwarepaketen
M4.178 Absicherung der Administrator- und Benutzerkonten beim IIS-Einsatz
M4.179 Schutz von sicherheitskritischen Dateien beim IIS-Einsatz
M4.180 Konfiguration der Authentisierungsmechanismen für den Zugriff auf den IIS
M4.181 Ausführen des IIS in einem separaten Prozess
M4.182 Überwachen des IIS-Systems
M4.183 Sicherstellen der Verfügbarkeit und Performance des IIS
M4.184 Deaktivieren nicht benötigter Dienste beim IISEinsatz
M4.185 Absichern von virtuellen Verzeichnissen und Web-Anwendungen beim IIS-Einsatz
M4.186 Entfernen von Beispieldateien und Administrations-Scripts des IIS
M4.187 Entfernen der FrontPage Server-Erweiterung des IIS
M4.188 Prüfen der Benutzereingaben beim IIS-Einsatz
M4.189 Schutz vor unzulässigen Programmaufrufen beim IIS-Einsatz
M4.190 Entfernen der RDS-Unterstützung des IIS
M4.191 Überprüfung der Integrität und Authentizität der Apache-Pakete
M4.192 Konfiguration des Betriebssystems für einen Apache-Webserver
M4.193 Sichere Installation eines Apache-Webservers
M4.194 Sichere Grundkonfiguration eines Apache-Webservers
M4.195 Konfiguration der Zugriffssteuerung beim Apache-Webserver
M4.196 Sicherer Betrieb eines Apache-Webservers
M4.197 Servererweiterungen für dynamische Webseiten beim Apache-Webserver
M4.198 Installation eines Apache-Webservers in einem chroot-Käfig
M4.199 Vermeidung gefährlicher Dateiformate
M4.200 Umgang mit USB-Speichermedien
M4.201 Sichere lokale Grundkonfiguration von Routern und Switches
M4.202 Sichere Netz-Grundkonfiguration von Routern und Switches
M4.203 Konfigurations-Checkliste für Router und Switches
M4.204 Sichere Administration von Routern und Switches
M4.205 Protokollierung bei Routern und Switches
M4.206 Sicherung von Switch-Ports
M4.207 Einsatz und Sicherung systemnaher z/OS Terminals
M4.208 Absichern des Start-Vorgangs von z/OS Systemen
M4.209 Sichere Grundkonfiguration von z/OS-Systemen
M4.210 Sicherer Betrieb des z/OS-Betriebssystems
M4.211 Einsatz des z/OS-Sicherheitssystems RACF
M4.212 Absicherung von Linux für zSeries
M4.213 Absichern des Login-Vorgangs unter z/OS
M4.214 Datenträgerverwaltung unter z/OS-Systemen
M4.215 Absicherung sicherheitskritischer z/OS-Dienstprogramme
M4.216 Festlegung der Systemgrenzen von z/OS
M4.217 Workload Management für z/OS-Systeme
M4.218 Hinweise zur Zeichensatzkonvertierung bei z/OS-Systemen
M4.219 Lizenzschlüssel-Management für z/OS-Software
M4.220 Absicherung von Unix System Services bei z/OS-Systemen
M4.221 Parallel-Sysplex unter z/OS
M4.222 Festlegung geeigneter Einstellungen von Sicherheitsproxies
M4.223 Integration von Proxy-Servern in das Sicherheitsgateway
M4.224 Integration von VPN-Komponenten in ein Sicherheitsgateway
M4.225 Einsatz eines Protokollierungsservers in einem Sicherheitsgateway
M4.226 Integration von Virenscannern in ein Sicherheitsgateway
M4.227 Einsatz eines lokalen NTP-Servers zur Zeitsynchronisation
M4.228 Nutzung der Sicherheitsmechanismen von PDAs
M4.229 Sicherer Betrieb von PDAs
M4.230 Zentrale Administration von PDAs
M4.231 Einsatz zusätzlicher Sicherheitswerkzeuge für PDAs
M4.232 Sichere Nutzung von Zusatzspeicherkarten
M4.233 Diese Maßnahme ist entfallen!
M4.234 Aussonderung von IT-Systemen
M4.235 Abgleich der Datenbestände von Laptops
M4.236 Zentrale Administration von Laptops
M4.237 Sichere Grundkonfiguration eines IT-Systems
M4.238 Einsatz eines lokalen Paketfilters
M4.239 Sicherer Betrieb eines Servers
M4.240 Einrichten einer Testumgebung für einen Server
M4.241 Sicherer Betrieb von Clients
M4.242 Einrichten einer Referenzinstallation für Clients
M4.243 Windows XP Verwaltungswerkzeuge
M4.244 Sichere Windows XP Systemkonfiguration
M4.245 Basiseinstellungen für Windows XP GPOs
M4.246 Konfiguration der Systemdienste unter Windows XP
M4.247 Restriktive Berechtigungsvergabe unter Windows XP
M4.248 Sichere Installation von Windows XP
M4.249 Windows XP Systeme aktuell halten
M4.250 Auswahl eines zentralen, netzbasierten Authentisierungsdienstes
M4.251 Arbeiten mit fremden IT-Systemen
M4.252 Sichere Konfiguration von Schulungsrechnern
M4.253 Schutz vor Spyware
M4.254 Sicherer Einsatz von drahtlosen Tastaturen und Mäusen
M4.255 Nutzung von IrDA-Schnittstellen
M4.256 Sichere Installation von SAP Systemen
M4.257 Absicherung des SAP Installationsverzeichnisses auf Betriebssystemebene
M4.258 Sichere Konfiguration des SAP ABAP-Stacks
M4.259 Sicherer Einsatz der ABAP-Stack Benutzerverwaltung
M4.260 Berechtigungsverwaltung für SAP Systeme
M4.261 Sicherer Umgang mit kritischen SAP Berechtigungen
M4.262 Konfiguration zusätzlicher SAP Berechtigungsprüfungen
M4.263 Absicherung von SAP Destinationen
M4.264 Einschränkung von direkten Tabellenveränderungen in SAP Systemen
M4.265 Sichere Konfiguration der Batch-Verarbeitung im SAP System
M4.266 Sichere Konfiguration des SAP Java-Stacks
M4.267 Sicherer Einsatz der SAP Java-Stack Benutzerverwaltung
M4.268 Sichere Konfiguration der SAP Java-Stack Berechtigungen
M4.269 Sichere Konfiguration der SAP System Datenbank
M4.270 SAP Protokollierung
M4.271 Virenschutz für SAP Systeme
M4.272 Sichere Nutzung des SAP Transportsystems
M4.273 Sichere Nutzung der SAP Java-Stack Software-Verteilung
M4.274 Sichere Grundkonfiguration von Speichersystemen
M4.275 Sicherer Betrieb eines Speichersystems
M4.276 Planung des Einsatzes von Windows Server 2003
M4.277 Absicherung der SMB-, LDAP- und RPCKommunikation unter Windows Server 2003
M4.278 Sichere Nutzung von EFS unter Windows Server 2003
M4.279 Erweiterte Sicherheitsaspekte für Windows Server 2003
M4.280 Sichere Basiskonfiguration von Windows Server 2003
M4.281 Sichere Installation und Bereitstellung von Windows Server 2003
M4.282 Sichere Konfiguration der IIS-Basis-Komponente unter Windows Server 2003
M4.283 Sichere Migration von Windows NT 4 Server und Windows 2000 Server auf Windows Server 2003
M4.284 Umgang mit Diensten unter Windows Server 2003
M4.285 Deinstallation nicht benötigter Client-Funktionen von Windows Server 2003
M4.286 Verwendung der Softwareeinschränkungsrichtlinie unter Windows Server 2003
M4.287 Sichere Administration der VoIP-Middleware
M4.288 Sichere Administration von VoIP-Endgeräten
M4.289 Einschränkung der Erreichbarkeit über VoIP
M4.290 Anforderungen an ein Sicherheitsgateway für den Einsatz von VoIP
M4.291 Sichere Konfiguration der VoIP-Middleware
M4.292 Protokollierung bei VoIP
M4.293 Sicherer Betrieb von Hotspots
M4.294 Sichere Konfiguration der Access Points
M4.295 Sichere Konfiguration der WLAN-Clients
M4.296 Einsatz einer geeigneten WLAN-Management-Lösung
M4.297 Sicherer Betrieb der WLAN-Komponenten
M4.298 Regelmäßige Audits der WLAN-Komponenten
M4.299 Authentisierung bei Druckern, Kopierern und Multifunktionsgeräten
M4.300 Informationsschutz bei Druckern, Kopierern und Multifunktionsgeräten
M4.301 Beschränkung der Zugriffe auf Drucker, Kopierer und Multifunktionsgeräte
M4.302 Protokollierung bei Druckern, Kopierern und Multifunktionsgeräten
M4.303 Einsatz von netzfähigen Dokumentenscann
M4.304 Verwaltung von Druckern
M4.305 Einsatz von Speicherbeschränkungen (Quotas)
M4.306 Umgang mit Passwort-Speicher-Tools
M4.307 Sichere Konfiguration von Verzeichnisdiensten
M4.308 Sichere Installation von Verzeichnisdiensten
M4.309 Einrichtung von Zugriffsberechtigungen auf Verzeichnisdienste
M4.310 Einrichtung des LDAP-Zugriffs auf Verzeichnisdienste
M4.311 Sicherer Betrieb von Verzeichnisdiensten
M4.312 Überwachung von Verzeichnisdiensten
M4.313 Bereitstellung von sicheren Domänen-Controllern
M4.314 Sichere Richtlinieneinstellungen für Domänen und Domänen-Controller
M4.315 Aufrechterhaltung der Betriebssicherheit von Active Directory
M4.316 Überwachung der Active Directory Infrastruktur
M4.317 Sichere Migration von Windows Verzeichnisdiensten
M4.318 Umsetzung sicherer Verwaltungsmethoden für Active Directory
M4.319 Sichere Installation von VPN-Endgeräten
M4.320 Sichere Konfiguration eines VPNs
M4.321 Sicherer Betrieb eines VPNs
M4.322 Sperrung nicht mehr benötigter VPN-Zugänge
M4.323 Synchronisierung innerhalb des Patch- und Änderungsmanagements
M4.324 Konfiguration von Autoupdate-Mechanismen beim Patch- und Änderungsmanagement
M5.001 Entfernen oder Deaktivieren nicht benötigter Leitungen
M5.002 Auswahl einer geeigneten Netz-Topologie
M5.003 Auswahl geeigneter Kabeltypen unter kommunikationstechnischer Sicht
M5.004 Dokumentation und Kennzeichnung der Verkabelung
M5.005 Schadensmindernde Kabelführung
M5.006 Diese Maßnahme ist entfallen!
M5.007 Netzverwaltung
M5.008 Regelmäßiger Sicherheitscheck des Netzes
M5.009 Protokollierung am Server
M5.010 Restriktive Rechtevergabe
M5.011 Diese Maßnahme ist entfallen!
M5.012 Diese Maßnahme ist entfallen!
M5.013 Geeigneter Einsatz von Elementen zur Netzkopplung
M5.014 Absicherung interner Remote-Zugänge
M5.015 Absicherung externer Remote-Zugänge
M5.016 Übersicht über Netzdienste
M5.017 Einsatz der Sicherheitsmechanismen von NFS
M5.018 Einsatz der Sicherheitsmechanismen von NIS
M5.019 Einsatz der Sicherheitsmechanismen von sendmail
M5.020 Einsatz der Sicherheitsmechanismen von rlogin, rsh und rcp
M5.021 Sicherer Einsatz von telnet, ftp, tftp und rexec
M5.022 Kompatibilitätsprüfung des Sender- und Empfängersystems
M5.023 Auswahl einer geeigneten Versandart für Datenträger
M5.024 Nutzung eines geeigneten Faxvorblattes
M5.025 Nutzung von Sende- und Empfangsprotokollen
M5.026 Telefonische Ankündigung einer Faxsendung
M5.027 Telefonische Rückversicherung über korrekten Faxempfang
M5.028 Telefonische Rückversicherung über korrekten Faxabsender
M5.029 Gelegentliche Kontrolle programmierter Zieladressen und Protokolle
M5.030 Aktivierung einer vorhandenen Callback-Option
M5.031 Geeignete Modem-Konfiguration
M5.032 Sicherer Einsatz von Kommunikationssoftware
M5.033 Absicherung der per Modem durchgeführten Fernwartung
M5.034 Einsatz von Einmalpasswörtern
M5.035 Einsatz der Sicherheitsmechanismen von UUCP
M5.036 Verschlüsselung unter Unix und Windows NT
M5.037 Einschränken der Peer-to-Peer-Funktionalitäten in einem servergestützten Netz
M5.038 Diese Maßnahme ist entfallen!
M5.039 Sicherer Einsatz der Protokolle und Dienste
M5.040 Diese Maßnahme ist entfallen!
M5.041 Sichere Konfiguration des Fernzugriffs unter Windows NT
M5.042 Sichere Konfiguration der TCP/IPNetzverwaltung unter Windows NT
M5.043 Sichere Konfiguration der TCP/IP-Netzdienste unter Windows NT
M5.044 Einseitiger Verbindungsaufbau
M5.045 Sicherheit von WWW-Browsern
M5.046 Einsatz von Stand-alone-Systemen zur Nutzung des Internets
M5.047 Einrichten einer Closed User Group
M5.048 Authentisierung mittels CLIP/COLP
M5.049 Callback basierend auf CLIP/COLP
M5.050 Authentisierung mittels PAP/CHAP
M5.051 Sicherheitstechnische Anforderungen an die Kommunikationsverbindung Telearbeitsrechner - Institution
M5.052 Sicherheitstechnische Anforderungen an den Kommunikationsrechner
M5.053 Schutz vor Mailbomben
M5.054 Schutz vor Mailüberlastung und Spam
M5.055 Kontrolle von Alias-Dateien und Verteilerlisten
M5.056 Sicherer Betrieb eines Mailservers
M5.057 Sichere Konfiguration der Mail-Clients
M5.058 Auswahl und Installation von Datenbankschnittstellen-Treibern
M5.059 Schutz vor DNS-Spoofing
M5.060 Auswahl einer geeigneten Backbone-Technologie
M5.061 Geeignete physikalische Segmentierung
M5.062 Geeignete logische Segmentierung
M5.063 Einsatz von GnuPG oder PGP
M5.064 Secure Shell
M5.065 Diese Maßnahme ist entfallen!
M5.066 Verwendung von SSL
M5.067 Verwendung eines Zeitstempel-Dienstes
M5.068 Einsatz von Verschlüsselungsverfahren zur Netzkommunikation
M5.069 Schutz vor aktiven Inhalten
M5.070 Adreßumsetzung - NAT (Network Address Translation)
M5.071 Intrusion Detection und Intrusion Response Systeme
M5.072 Deaktivieren nicht benötigter Netzdienste
M5.073 Sicherer Betrieb eines Faxservers
M5.074 Pflege der Faxserver-Adressbücher und der Verteillisten
M5.075 Schutz vor Überlastung des Faxservers
M5.076 Einsatz geeigneter Tunnel-Protokolle für die VPN-Kommunikation
M5.077 Bildung von Teilnetzen
M5.078 Schutz vor Erstellen von Bewegungsprofilen bei der Mobiltelefon-Nutzung
M5.079 Schutz vor Rufnummernermittlung bei der Mobiltelefon-Nutzung
M5.080 Schutz vor Abhören der Raumgespräche über Mobiltelefone
M5.081 Sichere Datenübertragung über Mobiltelefone
M5.082 Sicherer Einsatz von SAMBA
M5.083 Sichere Anbindung eines externen Netzes mit Linux FreeS/WAN
M5.084 Einsatz von Verschlüsselungsverfahren für die Lotus Notes Kommunikation
M5.085 Einsatz von Verschlüsselungsverfahren für Lotus Notes E-Mail
M5.086 Einsatz von Verschlüsselungsverfahren beim Browser-Zugriff auf Lotus Notes
M5.087 Vereinbarung über die Anbindung an Netze Dritter
M5.088 Vereinbarung über Datenaustausch mit Dritten
M5.089 Konfiguration des sicheren Kanals unter Windows 2000/XP
M5.090 Einsatz von IPSec unter Windows 2000/XP
M5.091 Einsatz von Personal Firewalls für Internet-PCs
M5.092 Sichere Internet-Anbindung von Internet-PCs
M5.093 Sicherheit von WWW-Browsern bei der Nutzung von Internet-PCs
M5.094 Sicherheit von E-Mail-Clients bei der Nutzung von Internet-PCs
M5.095 Sicherer E-Commerce bei der Nutzung von Internet-PCs
M5.096 Sichere Nutzung von Webmail
M5.097 Absicherung der Kommunikation mit Novell eDirectory
M5.098 Schutz vor Missbrauch kostenpflichtiger Einwahlnummern
M5.099 SSL/TLS-Absicherung für Exchange 2000
M5.100 Einsatz von Verschlüsselungs- und Signaturverfahren für die Exchange 2000 Kommunikation
M5.101 Entfernen nicht benötigter ODBC-Treiber beim IIS-Einsatz
M5.102 Installation von URL-Filtern beim IIS-Einsatz
M5.103 Entfernen sämtlicher Netzwerkfreigaben beim IIS-Einsatz
M5.104 Konfiguration des TCP/IP-Filters beim IIS Einsatz
M5.105 Vorbeugen vor SYN-Attacken auf den IIS
M5.106 Entfernen nicht vertrauenswürdiger Root-Zertifikate beim IIS-Einsatz
M5.107 Verwendung von SSL im Apache-Webserver
M5.108 Kryptographische Absicherung von E-Mail
M5.109 Einsatz eines E-Mail-Scanners auf dem Mailserver
M5.110 Absicherung von E-Mail mit SPHINX (S/MIME)
M5.111 Einrichtung von Access Control Lists auf Routern
M5.112 Sicherheitsaspekte von Routing-Protokollen
M5.113 Einsatz des VTAM Session Management Exit unter z/OS
M5.114 Absicherung der z/OS-Tracefunktionen
M5.115 Integration eines Webservers in ein Sicherheitsgateway
M5.116 Integration eines E-Mailservers in ein Sicherheitsgateway
M5.117 Integration eines Datenbank-Servers in ein Sicherheitsgateway
M5.118 Integration eines DNS-Servers in ein Sicherheitsgateway
M5.119 Integration einer Web-Anwendung mit Web-,Applikations- und Datenbank-Server in ein Sicherheitsgateway
M5.120 Behandlung von ICMP am Sicherheitsgateway
M5.121 Sichere Kommunikation von unterwegs
M5.122 Sicherer Anschluss von Laptops an lokale Netze
M5.123 Absicherung der Netzkommunikation unter Windows XP
M5.124 Netzzugänge in Besprechungs-, Veranstaltungsund Schulungsräumen
M5.125 Absicherung der Kommunikation von und zu SAP Systemen
M5.126 Absicherung der SAP RFC-Schnittstelle
M5.127 Absicherung des SAP Internet Connection Framework (ICF)
M5.128 Absicherung der SAP ALE (IDoc/BAPI) Schnittstelle
M5.129 Sichere Konfiguration der HTTP-basierten Dienste von SAP Systemen
M5.130 Absicherung des SANs durch Segmentierung
M5.131 Absicherung von IP-Protokollen unter Windows Server 2003
M5.132 Sicherer Einsatz von WebDAV unter Windows Server 2003
M5.133 Auswahl eines VoIP-Signalisierungsprotokolls
M5.134 Sichere Signalisierung bei VoIP
M5.135 Sicherer Medientransport mit SRTP
M5.136 Dienstgüte und Netzmanagement bei VoIP
M5.137 Einsatz von NAT für VoIP
M5.138 Einsatz von RADIUS-Servern
M5.139 Sichere Anbindung eines WLANs an ein LAN
M5.140 Aufbau eines Distribution Systems
M5.141 Regelmäßige Sicherheitschecks in WLANs
M5.142 Abnahme der IT-Verkabelung
M5.143 Laufende Fortschreibung und Revision der Netzdokumentation
M5.144 Rückbau der IT-Verkabelung
M5.145 Sicherer Einsatz von CUPS
M5.146 Netztrennung beim Einsatz von Multifunktionsgeräten
M5.147 Absicherung der Kommunikation mit Verzeichnisdiensten
M5.148 Sichere Anbindung eines externen Netzes mit OpenVPN
M5.149 Sichere Anbindung eines externen Netzes mit IPSec
M5.150 Durchführung von Penetrationstests
";

report = 'Prüfergebnisse gemäß IT-Grundschutz, 10. Ergänzungslieferung:\n\n\n';
log = string('');

foreach m (massnahmen) {
  result = get_kb_item("GSHB-10/" + m + "/result");
  desc = get_kb_item("GSHB-10/" + m + "/desc");
  name = get_kb_item("GSHB-10/" + m + "/name");
  mn = substr(m, 0, 1);
  mz = substr(m, 3);

if (!name){
  sm = mn + '.' + mz + ' ';
  name = egrep(pattern:sm, string:mtitel );
#  name = ereg_replace(string:name, pattern: '\\.(00|0)', replace:'.');
  name = ereg_replace(string:name, pattern: '^M', replace:'IT-Grundschutz M');
}

if (!result){
  if (name =~ "M(4|5)\.... Diese Maßnahme ist entfallen!") result = 'Prüfung dieser Maßnahme ist nicht notwendig, denn sie ist entfallen!';
  else if (m >!< depend) result = 'Prüfung dieser Maßnahme ist nicht implementierbar.';
  else result = 'Prüfroutine für diese Maßnahme ist nicht verfügbar.';
}

  if (!desc) {
    if (name =~ "M(4|5)\.... Diese Maßnahme ist entfallen!") desc = 'Prüfung dieser Maßnahme ist nicht notwendig, denn sie ist entfallen!';
    else if (m >!< depend) desc = 'Prüfung dieser Maßnahme ist nicht implementierbar.';
    else desc = 'Prüfroutine für diese Maßnahme ist nicht verfügbar.';
}
  report = report + name + 'Ergebnis:\t' + result +
           '\nDetails:\t' + desc + '\n\n';

  if (result >< 'error') result = 'ERR';
  else if (result >< 'Fehler') result = 'ERR';
  else if (result >< 'erfüllt') result = 'OK';
  else if (result >< 'nicht zutreffend') result = 'NS';
  else if (result >< 'nicht erfüllt') result = 'FAIL';
  else if (result >< 'unvollständig') result = 'NC';
  else if (result >< 'Prüfung dieser Maßnahme ist nicht implementierbar.') result = 'NA';
  else if (result >< 'Prüfroutine für diese Maßnahme ist nicht verfügbar.') result = 'NI';
  if (name =~ "M(4|5)\.... Diese Maßnahme ist entfallen!") result = 'DEP';
  ml = mn + "." + mz;
#  ml = ereg_replace(string:ml, pattern: '\\.(00|0)', replace:'.');
  txt = string("'");
  ip = get_host_ip ();
  log_desc = ereg_replace(pattern:'\n',replace:' ', string:desc);

  log = log + string('"' + ip + '"|"' + ml + '"|"' + result + '"|"' + log_desc + '"') + '\n';
#  log = log + string('"' + ip + '"|"' + ml + '"|"' + result + '"|"' + desc + '"') + '\n';
}

format = script_get_preference("Berichtformat");
if (format == "Text" || format == "Text und Tabellarisch") {
  security_note(port:0, proto: "IT-Grundschutz", data:report);
}
if (format == "Tabellarisch" || format == "Text und Tabellarisch") {
  log_message(port:0, proto: "IT-Grundschutz-T", data:log);
}

exit(0);
