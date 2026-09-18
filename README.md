- hacktricks-links is an extension that allows to recover links from Hacktricks of the associated port.

1. Put the extension file (.nse) in the nmap folder (`/usr/share/nmap/scripts`).
2. Then update Nmap internal DB: `sudo nmap --script-updatedb`
3. Then, the script will be triggered with option `-sC`
   
