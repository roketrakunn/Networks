## TCP Connect scan


# How it works

conn, err := net.DialTimeout("tcp", address, 1*time.Second)

This:
1. Sends SYN
2. Waits for SYN-ACK
3. Sends ACK
4. Connection established
5. Immediately closes it

*** If we get a connection:** Port is OPEN  
*** If we get an error:** Port is CLOSED or FILTERED


