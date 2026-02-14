# 🛡️Phishing Detection (Backed {not only} by AI)
### To setup, create the .env file:
I have used grok api (as it is free, upto a extent), if you want to change, change the code accordingly!
```
GROQ_API_KEY=gsk_rest_is_secret

### External APIs
VIRUSTOTAL_API_KEY=will_not_tell_you
GOOGLE_SAFE_BROWSING_API_KEY=not_at_all
ALIENVAULT_OTX_KEY=ok_here_it_is
PHISHTANK_API_KEY=passkey_13r31!#$Q#$11rr2

### Optional 
OPSWAT_API_KEY=if_provide_you_will_need_to_extend_the_code_since_I_have_used_only_a_stub
CISCO_UMBRELLA_KEY=same_with_this
```

Then, do `pip install backend/requirements.txt`

It runs both in docker and out of it. Using docker is a safer option, cause `headless browser` actually visits the website. To use docker, build using `docker-compose build` and then run using `docker-compose up`. 

Otherwise, `mv` to `phish/backend` and run `python app.py`.

In both case, visit `index.html` to get the interface.

### Packet capture permissions (Docker)
Live packet capture requires raw socket privileges in the backend container. The compose setup must run backend with `NET_RAW` + `NET_ADMIN` and root (or equivalent capabilities), otherwise Scapy sniffing will fail with `PermissionError: [Errno 1] Operation not permitted`.

## Some demo images
#### Things have changed a bit (this is older version) [but I was too lazy to upload. maybe you can check for yourself]
### Main screen (after analysis) [to see before analysis, repeat the steps mentioned before:)]
<img width="1100" height="866" alt="image" src="https://github.com/user-attachments/assets/bf6f9dcc-c6b0-487a-8674-cbf9a6aa58ad" />

### Analysis
<img width="1100" height="861" alt="image" src="https://github.com/user-attachments/assets/2ac0045d-7f3c-4a91-9795-958232504e76" />

### External Threat Intelligence
<img width="1100" height="870" alt="image" src="https://github.com/user-attachments/assets/9272a7a6-b032-4bf1-b8fb-e97934ce4602" />

### Behavior Analysis (Using headless browser)
<img width="1100" height="864" alt="image" src="https://github.com/user-attachments/assets/09375326-e927-4100-804c-30b8b51a8a1c" />






