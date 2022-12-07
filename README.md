# config firefox  
 
<dl><img src="https://www.mozilla.org/media/protocol/img/logos/firefox/browser/og.4ad05d4125a5.png" style="border-radius:18px"></dl>
1) Download firefox from origin website with this link:  
[Firefox website](https://www.mozilla.org/en-US/firefox/download/thanks/ "Firefox origin website")  
or you can download it from this address:  
[Mozilla FTP server](https://ftp.mozilla.org/pub/firefox/releases/ "Mozilla FTP server")  
find release do you want and download it.  
### first solution  
after downloading Firefox and you should decompress file so you can use this command:  
``` sh
tar -xvf firefox-[release number].tar.bz2
```
if the command doesn't work use this command:  
``` sh
tar -xvjf firefox-[release number].tar.bz2
```
now Firefox is there, open the firefox folder and run `firefox` file and program will be run.  
after you did this commands you can see `.mozilla` folder in your home directory, in that directory you will see two folder one is `firefox` and other one is `extensions`. open the firefox folder, and find your profile folder (you can determine that when you read profile.ini file)and open it, after that open the terminal from this directory and run this command in your terminal:  
``` sh
git clone https://github.com/ehsankarimi1/user.js
mv user.js test | mv test/user.js . | rm -rf test
```
after all of this enjoy.  
### second solution  
open the Firefox and put this `about:support` in your address bar. after page showed find Profile Directory in there and click on Open Directory. this is your profile directory and all of your setting will be there, after all of this put `user.js` file in this directory and close Firefox and rerun it, enjoy.  
  
