Author     :	Alagukannan
Date        :	09/07/2011
Version 1.0
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