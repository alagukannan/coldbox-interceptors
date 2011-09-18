<!-----------------------------------------------------------------------

Author     :	Alagukannan
Date        :	09/07/2011
Version : 1.0
Description :
This interceptor places the specified coldbox app or set of events based on the JSON rules file in maintenance mode by just updating the rulesFile and reinitiating the coldbox application.

Install:
 1. Drop the maintenance.cfc interceptor in to interceptor directory.
 2. Drop the maintenanceSchema.json.cfm in to your coldbox config directory.
 3. Write up a maintenance.json.cfm and drop it into your config directory.

Declaring the Interceptor:

Maintenance interceptor should be declared first or after deploy interceptor in the interceptor array queue since we don't want to run any other interceptor when the application itself is in maintenance mode. This interceptor also ends the interceptor chain if in maintenance mode.

{class="modulessample.interceptors.maintenance",properties = {rulesFile="config/maintenance.json.cfm",useregex=true}}

Properties:
Property            Type       Required  Default                              Description
useRegex            Boolean    false     true                                 Enables Regular expression pattern matchin.
rulesSchemaFile     String     false     config/maintenanceSchema.json.cfm    Location of the Json rules schema file which will be used to 
                                                                              validate the Json rules file.
rulesFile			String     true		 --									  Location of the Json maintenance rules file.		  


Rules:
The rules file content is formated in full JSON format which needs to validate against the below Rules Schema. 

{
   "type":"struct",
   "items":{
      "maintenanceModeEnabled":{//set to true and reintialize the framework to place the below patterns in maintenance mode.
         "type":"boolean",
		 "required": "true"
      },
      "rules":{
         "type":"array",
         "keys":{
            "type":"struct",
            "items":{
               "eventPattern":{ // is a list of events or if useRegex is set to true then it can be list of Regular expressions
                  "type":"string",
                  "required":"true"
               },
               "redirectURI":{ // Needs to be a valid URI and takes precendence over overrieEvent
                  "type":"string",
                  "required":"false"
               },
			   "overrideEvent":{ // this event will over ride any incoming event.
                  "type":"string",
                  "required":"false"
               }			   
            }
         }
      }
   }
} 

E.g Rules File:
{
   "maintenanceModeEnabled":"false",
   "rules":[
      {
         "eventPattern":"^general",
         "redirectURI":"http://www.google.com"
      },
      {
         "eventPattern":"^remote",
         "overrideEvent":"maintenance.remotemessage"
      }	  
   ]
}


	
Credits:
Based on Coldbox Security interceptor.
	
----------------------------------------------------------------------->
<cfcomponent hint="This is a maintenance interceptor"
			 output="false">

<!------------------------------------------- CONSTRUCTOR ------------------------------------------->
    <cfset instance = structnew()>
	<cffunction name="Configure" access="public" returntype="void" hint="This is the configuration method for your interceptors" output="false" >
		<cfscript>
			// Start processing properties
			if( not propertyExists('useRegex') or not isBoolean(getproperty('useRegex')) ){
				setProperty('useRegex',true);
			}
			
			if( not propertyExists('rulesSchemaFile') ){
				setProperty('rulesSchemaFile','config/maintenanceSchema.json.cfm');
			}
			
			// Rule Source Checks
			if( not propertyExists('rulesFile') ){
				$throw(message="The rules JSON File property has not been set.",type="interceptors.maintenance.rulesFilePropertyNotDefined");
			}		
		
			// Create the internal properties now
			setProperty('rules',Arraynew(1));
			setProperty('rulesLoaded',false);			
		</cfscript>
	</cffunction>

<!------------------------------------------- INTERCEPTION POINTS ------------------------------------------->

	<!--- After Aspects Load --->
	<cffunction name="afterAspectsLoad" access="public" returntype="void" output="false" >
		<!--- ************************************************************* --->
		<cfargument name="event" 		 required="true" type="any" hint="The event object.">
		<cfargument name="interceptData" required="true" type="struct" hint="interceptData of intercepted info.">
		<!--- ************************************************************* --->
		<cfscript>
			// Load Rules
			loadjsonRules();
		</cfscript>
	</cffunction>
	
	<!--- pre-process --->
	<cffunction name="preProcess" access="public" returntype="boolean" output="false" >
		<!--- ************************************************************* --->
		<cfargument name="event" 		 required="true" type="any" hint="The event object.">
		<cfargument name="interceptData" required="true" type="struct" hint="interceptData of intercepted info.">
		<!--- ************************************************************* --->
		<cfscript>
		
			// Check if inited already
			if( NOT getProperty('rulesLoaded') ){ afterAspectsLoad(arguments.event,arguments.interceptData); }
			
			//check if maintenance mode is enabled
			if (propertyExists('maintenanceModeEnabled') and getproperty('maintenanceModeEnabled') eq true){
				if( log.canDebug() )
					log.debug("We are in maintenance mode");				
				// Execute Rule processing 
				processRules(arguments.event,arguments.interceptData,arguments.event.getCurrentEvent());
				return true; //stop execution chain
			}else
				return false; //continue execution
		
		</cfscript>
	</cffunction>
	
	
	<!--- Process Rules --->
	<cffunction name="processRules" access="public" returntype="void" hint="Process security rules. This method is called from an interception point" output="false" >
		<!--- ************************************************************* --->
		<cfargument name="event" 		 required="true" type="any" hint="The event object.">
		<cfargument name="interceptData" required="true" type="struct" hint="interceptData of intercepted info.">
		<cfargument name="currentEvent"  required="true" type="string" hint="The event to check">
		<!--- ************************************************************* --->
		<cfscript>
			var x 		 = 1;
			var rules 	 = getProperty('rules');
			var rulesLen = arrayLen(rules);
			
			
			// Loop through Rules
			for(x=1; x lte rulesLen; x=x+1){
				// is current event in this override pattern? then stop execution
				if( structkeyexists(rules[x],'overrideEvent') and isEventInPattern(currentEvent,rules[x].overrideEvent) ){
					if( log.canDebug() ){
						log.debug("#currentEvent# found in over ride maintenance Event: #rules[x].overrideEvent#");
					}
					break;
				}
				
				// is currentEvent in maintaiencen mode list
				if( isEventInPattern(currentEvent,rules[x].eventPattern) ){				
					
					if( log.canDebug() ){
						log.debug("Current event=#currentEvent# matched for maintenance mode event pattern rule: #rules[x].toString()#.");
					}
					if (structkeyexists(rules[x],'redirectURI') and isValid("URL",rules[x].redirectURI))
						setNextEvent(URI = rules[x].redirectURI);//redirect to the specified URL
					else if (structkeyexists(rules[x],'overrideEvent'))					
						event.overrideevent(event = rules[x].overrideEvent); //override the current event
					break;
				}//end if current event did not match the event pattern.
				else{
					if( log.canDebug() ){
						log.debug("#currentEvent# Did not match this maintenance mode event pattern rule: #rules[x].toString()#");
					}
				}							
			}//end of rules checks
		</cfscript>
	</cffunction>
	
<!------------------------------------------- PRIVATE METHDOS ------------------------------------------->
	
	
	<!--- isEventInPattern --->
	<cffunction name="isEventInPattern" access="private" returntype="boolean" output="false" hint="Verifies that the current event is in a given pattern list">
		<!--- ************************************************************* --->
		<cfargument name="currentEvent" 	required="true" type="string" hint="The current event.">
		<cfargument name="patternList" 		required="true" type="string" hint="The list to test.">
		<!--- ************************************************************* --->
		<cfset var pattern = "">
		<!--- Loop Over Patterns --->
		<cfloop list="#arguments.patternList#" index="pattern">
			<!--- Using Regex --->
			<cfif getProperty('useRegex')>
				<cfif reFindNocase(trim(pattern),arguments.currentEvent)>
					<cfreturn true>
				</cfif>
			<cfelseif findNocase(trim(pattern),arguments.currentEvent)>
				<cfreturn true>
			</cfif>	
		</cfloop>	
		<cfreturn false>	
	</cffunction>
		
	<!--- Load XML Rules --->
	<cffunction name="loadjsonRules" access="private" returntype="void" output="false" hint="Load rules from JSON file">
		<cfscript>
			// Validate the XML File
			var rulesFilePath = "";
			var rulesSchemaFilePath = "";
			var jsonStructure = structnew();

			// Try to locate the schema path
			rulesSchemaFilePath = locateFilePath(reReplace(getProperty('rulesSchemaFile'),"^/",""));
			
			// Validate location
			if( len(rulesSchemaFilePath) eq 0 ){
				$throw("JSON maintenance rules schema file not found: #getProperty('rulesSchemaFile')#. Please check again.','','interceptors.maintenance.rulesScehamaFileNotFound");
			}

			// Set the correct expanded path now
			setProperty('rulesSchemaFilePath',rulesSchemaFilePath);
			
			// Try to locate the path
			rulesFilePath = locateFilePath(reReplace(getProperty('rulesFile'),"^/",""));
			
			// Validate location
			if( len(rulesFilePath) eq 0 ){
				$throw("JSON Rules file not found: #getProperty('rulesFile')#. Please check again.','','interceptors.maintenance.rulesFileNotFound");
			}
			
			// Set the correct expanded path now
			setProperty('rulesFilePath',rulesFilePath);
			
			
			//$dump(instance,1);
			//validate the json schema
			if (getPlugin('json').validate(doc = rulesFilePath, schema = rulesSchemaFilePath) eq false)
				$throw("JSON Rules file doesn't validate with Schema','#request.JSONSchemaErrors.toString()#','interceptors.maintenance.rulesFileinvalidjsonData");
							
			// Read in and parse
			jsonStructure = getPlugin('json').decode(getPlugin('fileutils').readFile(rulesFilePath));
						
			// set maintenance mode boolean flag
			// Start processing properties	
			setProperty("maintenanceModeEnabled",jsonStructure.maintenanceModeEnabled);
			
			//set the rules into memory
			setProperty('rules',jsonStructure.rules);			
			
			setProperty('rulesLoaded',true);	
		</cfscript>
	</cffunction>
	
	
	
</cfcomponent>