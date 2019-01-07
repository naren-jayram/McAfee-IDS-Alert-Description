import requests
import base64
import json
import datetime
import urllib3
import csv
import urllib2
import ssl
import os
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) #Suppress InsecureRequestWarning

# Configuration
nsm_host = " "                  # McAfee NSM Host
api_key = " "                   # This is NSM base64(username:password)
alert_id = " "                  # Alert ID from from IDS alert should come here
sensor_id = " "                 # Sensor ID from IDS alert should come here
event_class_id = " "            # NSP ID  ex: 0x4029d300
count = " "                     #count from IDS alert should come here
# End of Configuration

# Function to make a GET request to a resource and return the response content in json format
def get_request(resource):
    get_req = requests.get(url+resource, headers=headers, verify=False)
    return convert_response_to_json(get_req.content)

# Function to encode the credentials in base64. P.S: This is manadatory as per NSM API specs
def base64encode(u,p):
    user_pass = '%s:%s' % (u,p)
    return base64.b64encode(user_pass, 'utf-8')

 # Function to convert the response body to a json (dict type)
def convert_response_to_json(response):
    return json.loads(str(response))

try:
    sig_id_exists = "false"
    clean_event_class_id = str(event_class_id).strip()
    alert_uri = 'alerts/%s?sensorId=%s' %(alert_id,sensor_id)

    if not os.path.isfile('signature_definition.csv'):
        with open('signature_definition.csv', 'w+') as csvfile:
            csv_writer = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)
            header = ['signature ID', 'Definition']
            csv_writer.writerow(header)

    # Let's look for signature definition in csv file, which we have accumulated so far... This is because to reduce hits on McAfee NSM.
    with open('signature_definition.csv', 'r') as csvfile:
        reader = csv.reader(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)
        for row in reader:
            if clean_event_class_id in row[0]:
				alert_definition = row[1]
				print "Alert Description exists in CSV File!"
				print alert_definition
				sig_id_exists = "true"

	# If signature definition doesn't exists in csv file, we will fetch it from McAfee NSM.
	if sig_id_exists == "false":
		url = 'https://%s/sdkapi/' %nsm_host 
		headers = {'Accept':'application/vnd.nsm.v2.0+json','Content-Type':'application/json','NSM-SDK-API':api_key} 
		authentication = get_request('session') #This will authenticate the request and get the session id and user id
		auth_session = base64encode(authentication['session'], authentication['userId']) #Base 64 encode(session id:user id)
		headers['NSM-SDK-API'] = str(auth_session) #Updates the Header parameters with the proper authorization tokens
		alert_details = get_request(alert_uri)

		if count == 1:	#This condition is to confirm that IDS alert is not a suppressed one 
			try:
				alert_definition = alert_details['description']['definition']
				print alert_definition
				with open('signature_definition.csv', 'a') as csvfile:
					write_descriptor = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL ) 
					write_descriptor.writerow([clean_event_class_id,alert_definition])	#This will add new NSP ID and alert definition to csv file

			except:
				print ("I am sorry! couldn't find the alert definition in McAfee NSM")

except Exception as e:
    print e
