/*
 * Created on Jul 26, 2005
 *
 * TODO To change the template for this generated file go to
 * Window - Preferences - Java - Code Style - Code Templates
 */
package ch.but.props;

import java.io.FileInputStream;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Properties;

/**
 * @author hobo
 *
 * TODO To change the template for this generated type comment go to
 * Window - Preferences - Java - Code Style - Code Templates
 */

public class Props {

	  // value to hold root properties
	  protected Properties _props;
	  private static String _language = "en"; // default is english

	  public Props() { 
	    // load data from file only once
	    try {
	      _props = new Properties();

	      // load mainfile which describes the global files deployment
	      FileInputStream fis = new FileInputStream("/zpool/applic/tomcat/config/general.properties");
	      _props.load(fis);

	      // get file-element list from global properties
	      Enumeration names = _props.propertyNames();

	      // load all files found in global properties
	      while (names.hasMoreElements()) {
	      	String elementName =(String)names.nextElement();
	      	
	      	if (elementName.indexOf("file") != -1) {
	      		fis = new FileInputStream("config/" + _props.getProperty(elementName).concat(".properties"));
	      		_props.load(fis);
	      	}
	      }
	      
	      _language = _props.getProperty("language");
	    }
	    catch (Exception e) {
	      /**
	       * We can't go further if it fails reading all the properties.
	       * That's why it makes no sense to log silently
	       */
	      e.printStackTrace();
	    }
	  }
	  
	  /**
	   * Retruns the language property from the file.properties. Possible values eg.
	   * en, de, fr...
	   * 
	   * @return The language
	   */
	  public String getLanguage() {
	  	return _language;
	  }
	  
	  /**
	   * Returns the locale built from the language property.
	   * @return The Locale
	   */
	  public Locale getLocale() {
	  	return new Locale(_language);
	  }
	}