# IMPORTANT #
This code does not work on windows. Use Debian OS to run this code.

This code uses AF_PACKET function of socket module which is not available for windows.
Same goes for AF_INET.



## Some concepts ##

### 1) Ethernet Frame Header
<img width="772" alt="Screenshot 2023-02-21 211106" src="https://user-images.githubusercontent.com/72330781/232037131-961230ed-61d4-4563-b6d1-fec2afb14dce.png">


### 2) Mac Address unpacking
<img width="385" alt="after unpack" src="https://user-images.githubusercontent.com/72330781/232037208-6bfa6f90-e7c5-4384-a0d0-d12c4cd6d2f7.png">


### 3) IPv4 Header
![image](https://user-images.githubusercontent.com/72330781/232037926-6aa54b29-cc71-474c-b19e-9eaf345d442d.png)


### 4) ICMP packet
![image](https://user-images.githubusercontent.com/72330781/232047683-196dedc8-ed1a-4f32-8df4-72a254666e85.png)


### 5) TCP packet
![image](https://user-images.githubusercontent.com/72330781/232048758-c31a6a19-92c0-4bd5-ba89-47a968b25698.png)
