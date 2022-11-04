

Create a `.env` file and type down the important credentials for IBM Bucket.

It would look like this:

```python
COS_ENDPOINT="https://s3.jp-tok.cloud-object-storage.appdomain.cloud/" 
COS_API_KEY_ID="5438b65746574-i46b436464CT_gnuveye54874-7" 
COS_INSTANCE_CRN="crn:v1:bluemix:public:cloud-object-storage:global:a/7b487h46464w8765bv756nmh386535:c22fe22d-22c4-4cc1-a2db-b54b37f43::" 
```

Don't worry, this is not the real credentials of mine, just placeholders ;)

You can find these credentials under your IBM Cloud Storage Bucket Service Credentials. 
If you can't find them then you have to create the Service Credentials first. 
Also make sure to give public access to the objects inside your Bucket.

Place the `.env` file in the root folder and you're good to go.
