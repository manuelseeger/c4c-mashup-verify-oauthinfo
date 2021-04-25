# Introduction 
Demo server implementation of verifying the OAuthInfo object from the C4C Mashup API. 

# Getting Started
```
npm install
npm run start
```

# Docs
index.js contains the full server demo
public/stat.html contains the static HTML code pasted to the C4C mashup through the C4C admin UI.

## Server

C4C send the InfoObject from the mashup API to the server through a C4C server side webservice. The webservice does a POST with the InfoObject in a form-encoded string in the variable "payload". The infoobject is stringified JSON. 

Auth options for the receiver: Basic (OAuth 1.0 available according to documentation but unclear how it is supposed to work). 



