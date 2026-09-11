A Bucket of Phish 
🧠 Challenge Summary

An attacker (DarkInjector) created a phishing website hosted on AWS S3 to steal user credentials.
Objective:

Identify and retrieve the list of victim users

⸻

🔍 Step 1 — Analyze the Given URL

http://darkinjector-phish.s3-website-us-west-2.amazonaws.com

Key observation:
	•	Hosted on AWS S3 static website
	•	Format reveals:
	•	Bucket name: darkinjector-phish
	•	Region: us-west-2

⸻

🔍 Step 2 — Inspect the Phishing Page

Viewed page source:

<form action="/login" method="POST">

Insight:
	•	Static S3 sites cannot process backend POST requests
	•	Indicates:
Either fake form OR data stored elsewhere in the bucket

⸻

🔍 Step 3 — Enumerate S3 Bucket

Tried direct bucket access:

http://darkinjector-phish.s3.amazonaws.com/?list-type=2


⸻

✅ Success — Bucket Listing Enabled

<Key>captured-logins-093582390</Key>
<Key>index.html</Key>

Critical finding:

captured-logins-093582390 likely contains stolen credentials

⸻

🔍 Step 4 — Retrieve Victim Data

Accessed file:

http://darkinjector-phish.s3.amazonaws.com/captured-logins-093582390


⸻

🎯 Result

File contained:
	•	Captured user credentials / victim list
	•	Embedded flag

⸻

🏁 Flag

THM{this_is_not_what_i_meant_by_public}


⸻

🧠 Technical Analysis

Root Cause

The attacker made a critical OPSEC mistake:
	•	S3 bucket was:
	•	❌ Publicly accessible
	•	❌ Listable
	•	❌ No access restrictions

⸻

Attack Flow
	1.	User visits phishing page
	2.	Enters credentials
	3.	Data is stored in S3 bucket
	4.	Bucket is publicly exposed
	5.	Anyone can retrieve stolen data

⸻

🧠 Key Lessons

1. S3 Misconfiguration = Data Exposure
	•	Public buckets can leak sensitive data instantly

⸻

2. Bucket Listing is Dangerous

/?list-type=2

	•	Reveals all stored objects
	•	Makes enumeration trivial

⸻

3. Static Hosting ≠ Secure Backend
	•	S3 static sites cannot safely handle authentication logic

⸻

4. Always Check Cloud Storage

In phishing investigations:
	•	Look beyond webpage
	•	Check:
	•	Storage buckets
	•	APIs
	•	JS endpoints

⸻

🔐 Prevention Measures
	•	Disable public access unless required
	•	Use IAM policies and bucket policies
	•	Disable bucket listing
	•	Encrypt sensitive data
	•	Separate frontend and backend storage

⸻

🎯 Final Conclusion
	•	Vulnerability: Public S3 bucket exposure
	•	Sensitive data: Captured victim credentials
	•	Flag recovered from exposed object

