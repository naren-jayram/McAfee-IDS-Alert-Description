### McAfee NSM IDS Alert Definition Grabber
This script pulls the alert description for a given IDS alert from McAfee NSM  

### Pre-requisite
Access to McAfee NSM.

### Usage
```
python nsm_get_description.py
```

### Additional Info
Script will save the alert description in *signature_definition.csv* for future lookups in order to reduce burden on McAfee NSM. Refrence is NSP ID /event_class_id.

### USE CASE
Consider a scenario that you are pushing IDS alerts out of McAfee NSM to any of your log management tool, parsing it to extract atleast below fields. Now, for some reason you need definition/description associated with an IDS alert. If you have a script already ready to pull these fields from log management tool, you can extend it by including this code.
```
fields: Alert ID, Sensor ID, NSP ID, Attack Count
```