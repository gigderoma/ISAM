importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importClass(Packages.com.ibm.security.access.user.UserLookupHelper);
importClass(Packages.com.ibm.security.access.user.User);
importPackage(Packages.com.ibm.security.access.httpclient);

// Infomap Example username & Password module that authentication to IGI via REST API and returns PAC to Webseal
// in a form that a valid formatted LTPA token can be created and sent to IGI via LTPA junction.
// It also has a retry count mechanism to control failed login
//
//
// A mapping rule invoked by the InfoMap authentication mechanism has the following parameters available
//
// Input:
//
// var:context - type:Context -  the same session context which is passed into the
// authsvc_credential mapping rule. Makes available the users session
// attributes. May be null if unauthenticated. 
//
// var:state - type:Map - Any values placed in the users state by prior invocations of
// this instance of the InfoMap authentication mechanism. Will not be null.
// Unused.
//
// Output:
//
// var:page - type:String - The page template to be displayed if this rule
// returns false, modify to return a different page. Will be populated with the
// configured page, overwrite to change.
//
// var:macros - type:Map<String, String> - Values to populate on the returned
// template page. Is an empty map passed in. The template page bundled with this sample will display an error if "@ERROR_MESSAGE@" is set.
//
// var:success - type:bool - If set to TRUE, the policy will continue. If set to FALSE, the template page in 'page' will be presented to the user.
//
// Also note:
// If we set success to false and populate macros["@ERROR_MESSAGE@"], the template page will show that error.
//

var debug = true;
var failpwdcount = 1;

// Get the failpwdcounter from session
var failpwdcountStr = context.get(Scope.SESSION, "urn:infomap:failpwdcounter", "failpwdcounter");

if (failpwdcountStr != null) {
    failpwdcount = parseInt(failpwdcountStr);
}


// Get username whatever fromat it is  from request parameters
 var username = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "username");
 IDMappingExtUtils.traceString("username from request: " + username);

 // Get the password  from request parameters
 var password = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "password");
 IDMappingExtUtils.traceString("password from request: " + password);


 
 // let's go 
if(username != null && username != "" && password != null && password != "" && failpwdcount < 3) {
	
	// connection properties
	var headers = new Headers();
	headers.addHeader("Content-Type", "text/xml");
  headers.addHeader("Realm", "IDEAS");
  
	var endpoint = "https://igi-524-app.four.support.it:9343/igi/v2/security/login";
	var httpsTrustStore = "pdsrv";
	var clientKeyStore = null;
	var clientKeyAlias = null;
  var sslLev = "TLSv1.2";


/* hr will be a com.ibm.security.access.httpclient.HttpResponse */
IDMappingExtUtils.traceString("endpoint: " + endpoint + " httpsTrustStore: " + httpsTrustStore + " clientKeyStore: " + clientKeyStore + " clientKeyAlias: " + clientKeyAlias);


	/**
	 * httpGet(String url, Map headers, String httpsTrustStore,
	 * String basicAuthUsername,String basicAuthPassword, String
	 * clientKeyStore,String clientKeyAlias, String SSL);
	 */
	var hr = HttpClient.httpGet(endpoint, headers, httpsTrustStore, username, password, clientKeyStore, clientKeyAlias, sslLev);
	if (hr != null) {
		var code = hr.getCode(); // this is int
		var body = hr.getBody(); // this is java.lang.String

		if (debug) {
			IDMappingExtUtils.traceString("code: " + code);
			IDMappingExtUtils.traceString("body: " + body);
		}

		         // sanity check the response code and body - this is "best-effort"
		if (code != 200) {
			IDMappingExtUtils.traceString("username :" + username + " not verified");
            // return the same page rather than continuing authentication
			success.setValue(false); 
			macros.put("@ERROR_MESSAGE@","Invalid ISIG credential");
		}
		else {
			          // add user in the session context for later processing with authsvc_credential mapp
	    context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "username", username);
                // add attribute credentials that properly build PAC for ltpa token with short name
      context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "AZN_CRED_REGISTRY_ID", username);
      context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "AZN_CRED_AUTHZN_ID", username);   
		  success.setValue(true); 
		}

	}
 else 
	success.setValue(false); // return the same page again and again
}
   
else 
	success.setValue(false); // return the same page again and again
