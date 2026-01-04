


# مثال تست Open Redirect
https://target.com/login?redirect=https://evil.com
https://target.com/home?next=javascript:alert(1)

# مثال IDOR
https://target.com/user/123 → https://target.com/user/124

# مثال DOM XSS
https://target.com/search#<svg onload=alert(1)>

# WebSocket
wscat -c ws://target.com/ws
> {"cmd":"whoami","auth":"admin"}
